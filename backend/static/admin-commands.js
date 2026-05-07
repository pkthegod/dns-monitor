// admin-commands.js — extraido de admin.html (Fase B2 do refactor)
// Diagnostico, historico de comandos, modal de resultado, DNS Trace + DIG.
// Depende de admin-agents.js (compartilha state diagHostname, esc/fmtDate/canWrite/etc).

// LL1: badge "untrusted output" — todo lugar que renderiza dado vindo do
// agente ganha esse banner. Awareness pro operador: agente comprometido
// pode injetar prompt-injection no output. Nao colar em LLM cegamente.
const UNTRUSTED_TOOLTIP = 'Output do agente — dado controlavel se o host for comprometido. Sanitize antes de colar em IA/LLM (risco de prompt injection).';
function untrustedBanner() {
  return `<div class="untrusted-banner" title="${UNTRUSTED_TOOLTIP}">output do agente — nao cole em LLM sem revisar</div>`;
}

// -- Diagnostic modal -----------------------------------------------------
function openDiagModal(hostname) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  diagHostname = hostname;
  document.getElementById('diag-hostname-label').textContent = `// ${hostname}`;
  document.getElementById('diag-result-area').innerHTML = '';
  document.getElementById('diag-run-btn').disabled = false;
  document.getElementById('diag-modal').classList.add('open');
}

function closeDiagModal() {
  document.getElementById('diag-modal').classList.remove('open');
  if (diagPollTimer) { clearInterval(diagPollTimer); diagPollTimer = null; }
  diagHostname = null;
}

document.getElementById('diag-modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeDiagModal();
});

async function runDiagnostic() {
  if (!diagHostname) return;
  const scriptId = document.getElementById('diag-script-select').value;
  const runBtn   = document.getElementById('diag-run-btn');
  const area     = document.getElementById('diag-result-area');

  runBtn.disabled = true;
  area.innerHTML = `
    <div class="diag-result">
      <div class="diag-waiting">
        <div class="spinner"></div>
        <span>Enfileirando comando para <strong>${esc(diagHostname)}</strong>…</span>
      </div>
    </div>`;

  let cmdId;
  try {
    const resp = await apiFetch('/commands', {
      method: 'POST',
      body: JSON.stringify({
        hostname: diagHostname,
        command: 'run_script',
        params: scriptId,
        issued_by: 'admin-panel',
        expires_hours: 1,
      }),
    });
    cmdId = resp.id;
  } catch (e) {
    area.innerHTML = `<div class="diag-result"><div class="inline-msg inline-error"><span class="inline-msg-icon">${ICONS.error}</span><p>${esc(e.message)}</p></div></div>`;
    runBtn.disabled = false;
    return;
  }

  area.innerHTML = `
    <div class="diag-result">
      <div class="diag-waiting">
        <div class="spinner"></div>
        <span>Aguardando o agente executar o diagnóstico… (id=${cmdId})</span>
      </div>
      <div class="dim" style="margin-top:8px;font-size:.7rem">O agente executa no próximo poll de comandos.</div>
    </div>`;

  let attempts = 0;
  const maxAttempts = 40; // 40 × 3s = 2 min
  diagPollTimer = setInterval(async () => {
    attempts++;
    if (attempts > maxAttempts) {
      clearInterval(diagPollTimer);
      diagPollTimer = null;
      area.innerHTML = `<div class="diag-result"><div class="diag-waiting"><span>Timeout: o agente não respondeu em 2 minutos. Verifique o histórico de comandos.</span></div></div>`;
      runBtn.disabled = false;
      return;
    }
    try {
      const cmd = await apiFetch(`/commands/${cmdId}/status`);
      if (cmd.status === 'pending') return;
      clearInterval(diagPollTimer);
      diagPollTimer = null;
      runBtn.disabled = false;
      renderDiagResult(cmd);
      await loadHistory();
    } catch (_) { /* continua polling */ }
  }, 3000);
}

function renderDiagResult(cmd) {
  const area = document.getElementById('diag-result-area');
  const banner = untrustedBanner();  // LL1: output abaixo e do agente
  if (cmd.status === 'failed') {
    const raw = cmd.result || 'Erro desconhecido';
    // Caso comum: agente em versao antiga nao conhece script novo.
    // O agente retorna "Script desconhecido: X. Disponíveis: ['...', '...']"
    // — converter em hint actionable em vez de mensagem tecnica solta.
    const unknownMatch = raw.match(/Script desconhecido:\s*(\S+)/);
    if (unknownMatch) {
      const requested = unknownMatch[1];
      const available = (raw.match(/Disponíveis:\s*(\[.+?\])/) || [])[1] || '?';
      area.innerHTML = banner + `
        <div class="diag-result">
          <div class="inline-msg inline-warn">
            <span class="inline-msg-icon">${ICONS.warning}</span>
            <div>
              <strong>Script "${esc(requested)}" nao disponivel neste agente</strong>
              <p style="margin:6px 0 0;font-size:.78rem">
                O agente esta numa versao antiga que nao conhece este script.<br>
                <strong>Atualize o agente primeiro</strong> (botao Update no menu ⋯ da linha do agente, ou bulk Update).<br>
                Apos restart, o teste deve funcionar.
              </p>
              <p class="dim" style="margin:8px 0 0;font-size:.7rem;font-family:var(--font-mono)">
                Scripts disponiveis no agente: ${esc(available)}
              </p>
            </div>
          </div>
        </div>`;
      return;
    }
    // dns_validate quando nao detecta servico DNS — retorna JSON estruturado.
    // Tentar parse pra renderizar bonito; fallback texto bruto.
    try {
      const failedData = JSON.parse(raw);
      if (Array.isArray(failedData.checks) && failedData.checks.length) {
        const checksHtml = failedData.checks.map(c => {
          const iconClass = { ok:'icon-ok', fail:'icon-fail', skip:'icon-skip', info:'icon-info', warn:'icon-warn' }[c.status] || 'icon-fail';
          return `<div class="diag-check"><span class="diag-check-icon ${iconClass}">${c.status}</span><span>${esc(c.message)}</span></div>`;
        }).join('');
        area.innerHTML = banner + `
          <div class="diag-result">
            <div class="diag-header">
              <span class="pill pill-failed">FALHOU</span>
              <span class="diag-summary-text diag-summary-fail">${esc(failedData.summary || 'Diagnostico falhou')}</span>
            </div>
            <div class="diag-checks">${checksHtml}</div>
          </div>`;
        return;
      }
    } catch(_) { /* nao e JSON estruturado, segue pro fallback */ }
    area.innerHTML = banner + `<div class="diag-result"><div class="inline-msg inline-error"><span class="inline-msg-icon">${ICONS.error}</span><p>${esc(raw)}</p></div></div>`;
    return;
  }
  let data;
  try {
    data = JSON.parse(cmd.result);
  } catch (_) {
    area.innerHTML = banner + `<div class="diag-result"><div class="dim" style="white-space:pre-wrap;font-size:.78rem">${esc(cmd.result)}</div></div>`;
    return;
  }
  const ok = data.error_count === 0;
  const checksHtml = (data.checks || []).map(c => {
    const iconClass = { ok:'icon-ok', fail:'icon-fail', skip:'icon-skip', info:'icon-info', warn:'icon-warn' }[c.status] || 'icon-skip';
    return `<div class="diag-check">
      <span class="diag-check-icon ${iconClass}">${c.status}</span>
      <span>${esc(c.message)}</span>
    </div>`;
  }).join('');

  area.innerHTML = banner + `
    <div class="diag-result">
      <div class="diag-header">
        <span class="pill ${ok ? 'pill-done' : 'pill-failed'}">${ok ? 'SAUDÁVEL' : 'PROBLEMAS'}</span>
        <span class="diag-summary-text ${ok ? 'diag-summary-ok' : 'diag-summary-fail'}">${esc(data.summary || '')}</span>
        <span class="dim" style="margin-left:auto">${data.checks ? data.checks.length : 0} checks</span>
      </div>
      <div class="diag-checks">${checksHtml}</div>
    </div>`;
}

// -- Load history ---------------------------------------------------------
async function loadHistory() {
  const tbody = document.getElementById('tbody-history');
  if (!whoami()) {
    tbody.innerHTML = '<tr><td colspan="7" class="dim" style="padding:14px">Sessao necessaria para ver o historico.</td></tr>';
    return;
  }
  try {
    const rows = await apiFetch('/commands/history?limit=50');
    document.getElementById('badge-history').textContent = `${rows.length} recentes`;

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="dim" style="padding:14px">Nenhum comando registrado.</td></tr>';
      return;
    }

    tbody.innerHTML = rows.map(r => {
      let resultPreview = '—';
      if (r.result) {
        // LL1: r.result vem do agente — marca como untrusted (tooltip + style).
        // Para run_script, mostrar resumo do JSON
        if (r.command === 'run_script') {
          try {
            const d = JSON.parse(r.result);
            // CSP refactor B: data-result com encodeURIComponent evita
            // escapes complexos no innerHTML; showResultModalEv decodifica.
            resultPreview = `<span class="pill ${d.error_count === 0 ? 'pill-done' : 'pill-failed'} untrusted-marker" title="${UNTRUSTED_TOOLTIP}" style="cursor:pointer" data-action="showResultModalEv" data-result="${encodeURIComponent(r.result)}">
              ${d.error_count === 0 ? 'SAUDÁVEL' : d.error_count + ' FALHA(S)'} — ${esc(d.summary || '')}
            </span>`;
          } catch (_) {
            resultPreview = `<span class="dim untrusted-marker" title="${UNTRUSTED_TOOLTIP}">${esc(r.result).slice(0,60)}${r.result.length > 60 ? '…' : ''}</span>`;
          }
        } else {
          resultPreview = `<span class="dim untrusted-marker" title="${UNTRUSTED_TOOLTIP}\n\nConteudo: ${esc(r.result)}">${esc(r.result).slice(0,60)}${r.result.length > 60 ? '…' : ''}</span>`;
        }
      }
      return `
      <tr>
        <td><strong>${esc(r.hostname)}</strong></td>
        <td><code>${esc(r.command)}${r.command === 'run_script' && r.params ? ` [${esc(r.params)}]` : ''}</code></td>
        <td><span class="dim">${esc(r.issued_by) || '—'}</span></td>
        <td><span class="dim">${fmtDate(r.issued_at)}</span></td>
        <td><span class="dim">${fmtDate(r.executed_at)}</span></td>
        <td><span class="pill pill-${esc(r.status)}">${esc(r.status).toUpperCase()}</span></td>
        <td>${resultPreview}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="inline-msg inline-error fade-in"><span class="inline-msg-icon">${ICONS.error}</span><div><strong>Erro ao carregar historico</strong><p>${esc(e.message)}</p></div></div></td></tr>`;
  }
}

// -- Result modal (para ver resultado completo do diagnóstico) ------------
function showResultModal(resultJson) {
  let data;
  try { data = JSON.parse(resultJson); } catch (_) { return; }
  // Reutiliza o modal de diagnóstico só para exibir
  document.getElementById('diag-hostname-label').textContent = `// resultado`;
  document.getElementById('diag-result-area').innerHTML = '';
  document.getElementById('diag-run-btn').style.display = 'none';
  document.getElementById('diag-script-select').parentElement.style.display = 'none';
  document.getElementById('diag-modal').classList.add('open');
  renderDiagResult({ status: 'done', result: resultJson });
}

// -- DNS Trace modal ------------------------------------------------------
let traceHostname  = null;
let tracePollTimer = null;

document.getElementById('trace-resolver').addEventListener('change', function () {
  document.getElementById('trace-custom-wrap').style.display =
    this.value === 'custom' ? '' : 'none';
});

function openTraceModal(hostname) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  traceHostname = hostname;
  document.getElementById('trace-hostname-label').textContent = `// ${hostname}`;
  document.getElementById('trace-area').innerHTML = '';
  document.getElementById('trace-run-btn').disabled = false;
  document.getElementById('trace-modal').classList.add('open');
  document.getElementById('trace-domain').focus();
}

function closeTraceModal() {
  document.getElementById('trace-modal').classList.remove('open');
  if (tracePollTimer) { clearInterval(tracePollTimer); tracePollTimer = null; }
  // Cleanup ambos mapas pra evitar leak de listeners + timeouts pendentes +
  // WebGL context se usuario fechar antes da animacao terminar.
  if (window.TraceMap) {
    const m2d = document.getElementById('trace-map-2d');
    const m3d = document.getElementById('trace-map-3d');
    if (m2d) window.TraceMap.destroy(m2d);
    if (m3d) window.TraceMap.destroy(m3d);
  }
  traceHostname = null;
}

document.getElementById('trace-modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeTraceModal();
});

function getTraceResolver() {
  const sel = document.getElementById('trace-resolver').value;
  if (sel === 'custom') return document.getElementById('trace-custom-resolver').value.trim() || '127.0.0.1';
  return sel;
}

async function runTrace() {
  if (!traceHostname) return;
  const domain   = document.getElementById('trace-domain').value.trim();
  const resolver = getTraceResolver();
  if (!domain) { toast.warn('Informe um dominio.'); return; }

  const runBtn = document.getElementById('trace-run-btn');
  const area   = document.getElementById('trace-area');
  runBtn.disabled = true;

  area.innerHTML = `<div class="trace-area"><div class="diag-waiting"><div class="spinner"></div><span>Enfileirando trace para <strong>${esc(traceHostname)}</strong>…</span></div></div>`;

  let cmdId;
  try {
    const resp = await apiFetch('/commands', {
      method: 'POST',
      body: JSON.stringify({
        hostname:     traceHostname,
        command:      'run_script',
        params:       JSON.stringify({ script: 'dig_trace', domain, resolver }),
        issued_by:    'admin-panel',
        expires_hours: 1,
      }),
    });
    cmdId = resp.id;
  } catch (e) {
    area.innerHTML = `<div class="trace-area"><div class="inline-msg inline-error"><span class="inline-msg-icon">${ICONS.error}</span><p>${esc(e.message)}</p></div></div>`;
    runBtn.disabled = false;
    return;
  }

  area.innerHTML = `
    <div class="trace-area">
      <div class="diag-waiting"><div class="spinner"></div>
      <span>Aguardando agente executar dig +trace… (cmd id=${cmdId})</span></div>
      <div class="dim" style="margin-top:8px;font-size:.7rem">O agente executa no próximo poll de comandos.</div>
    </div>`;

  let attempts = 0;
  tracePollTimer = setInterval(async () => {
    if (++attempts > 40) {
      clearInterval(tracePollTimer); tracePollTimer = null;
      area.innerHTML = `<div class="trace-area"><div class="diag-waiting"><span>Timeout: agente não respondeu em 2 min.</span></div></div>`;
      runBtn.disabled = false;
      return;
    }
    try {
      const cmd = await apiFetch(`/commands/${cmdId}/status`);
      if (cmd.status === 'pending') return;
      clearInterval(tracePollTimer); tracePollTimer = null;
      runBtn.disabled = false;
      await renderTraceResult(cmd);
      await loadHistory();
    } catch (_) {}
  }, 3000);
}

async function renderTraceResult(cmd) {
  const area = document.getElementById('trace-area');
  if (cmd.status === 'failed') {
    area.innerHTML = `<div class="trace-area"><div class="inline-msg inline-error"><span class="inline-msg-icon">${ICONS.error}</span><p>${esc(cmd.result || 'Erro desconhecido')}</p></div></div>`;
    return;
  }
  let data;
  try { data = JSON.parse(cmd.result); } catch (_) {
    area.innerHTML = `<div class="trace-area"><pre style="font-size:.75rem;color:var(--text-mid);white-space:pre-wrap">${esc(cmd.result)}</pre></div>`;
    return;
  }
  if (data.error && !data.trace) {
    area.innerHTML = `<div class="trace-area"><div class="diag-error">${esc(data.error)}</div></div>`;
    return;
  }

  // Collect all IPs for geolocation
  const ips = new Set();
  (data.trace || []).forEach(h => { if (h.server_ip) ips.add(h.server_ip); });
  (data.query?.answers || []).forEach(a => { if (a.value) ips.add(a.value); });

  // Show skeleton while fetching geo
  area.innerHTML = buildTraceHtml(data, {});
  attachTraceTabs(data, {});
  document.querySelectorAll('.trace-geo-loading').forEach(el => el.textContent = 'obtendo geo…');

  let geoMap = {};
  try { geoMap = await fetchGeo([...ips]); } catch (_) {}

  // Re-render with geo data
  area.innerHTML = buildTraceHtml(data, geoMap);
  attachTraceTabs(data, geoMap);
}

// Conecta handlers das abas Lista/Mapa 2D no container do trace.
// Lazy: o mapa Leaflet so e instanciado quando a aba "Mapa 2D" e ativada
// pela primeira vez (poupa render de mapa que talvez nao seja visualizado).
function attachTraceTabs(data, geoMap) {
  const tabs = document.querySelectorAll('.trace-area .trace-tab');
  if (!tabs.length) return;
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.classList.contains('trace-tab-disabled')) return;
      const tab = btn.getAttribute('data-tab');
      // Marca aba ativa
      document.querySelectorAll('.trace-area .trace-tab').forEach(b => b.classList.remove('trace-tab-active'));
      btn.classList.add('trace-tab-active');
      // Mostra panel correspondente
      document.querySelectorAll('.trace-area .trace-tab-panel').forEach(p => {
        p.style.display = p.getAttribute('data-panel') === tab ? '' : 'none';
      });
      // Lazy-init dos mapas quando aba ativada pela primeira vez.
      // Defer com rAF: o panel acabou de virar display:'' nesta linha; sem
      // wait, container.clientWidth ainda e 0 (browser nao reflowou) e o
      // canvas WebGL/Leaflet nasce com tamanho errado, vazando pra fora.
      if (tab === 'map2d') {
        const container = document.getElementById('trace-map-2d');
        if (container && window.TraceMap && !container._traceMap) {
          requestAnimationFrame(() => {
            window.TraceMap.render2D(container, data.trace || [], geoMap || {});
          });
        }
      } else if (tab === 'map3d') {
        const container = document.getElementById('trace-map-3d');
        if (container && window.TraceMap && !container._traceGlobe) {
          requestAnimationFrame(() => {
            window.TraceMap.render3D(container, data.trace || [], geoMap || {});
          });
        }
      }
    });
  });
}

function buildTraceHtml(data, geoMap) {
  const q = data.query || {};
  const hops = data.trace || [];

  // Query summary bar
  const qStatus   = q.status || '?';
  const qAnswers  = (q.answers || []).map(a => a.value).join(', ') || '—';
  const qLatency  = q.latency_ms != null ? `${q.latency_ms}ms` : '?ms';
  const qOk       = qStatus === 'NOERROR' && (q.answers || []).length > 0;
  const qSumHtml  = `
    <div class="trace-query-summary">
      <span class="trace-query-label">Consulta direta</span>
      <span class="trace-query-status ${qOk ? 'status-noerror' : 'status-fail'}">${esc(qStatus)}</span>
      <span style="color:var(--text-mid)">${esc(qAnswers)}</span>
      <span class="pill ${qOk ? 'pill-done' : 'pill-failed'}" style="font-size:.65rem">${qLatency}</span>
      ${data.trace_error ? `<span style="color:var(--orange);font-size:.7rem">${esc(data.trace_error)}</span>` : ''}
    </div>`;

  if (!hops.length) {
    return `<div class="trace-area">${untrustedBanner()}${qSumHtml}<div class="diag-waiting"><span>Sem dados de trace disponíveis.</span></div></div>`;
  }

  // Determine hop types
  function hopType(i, total) {
    if (i === 0) return ['ROOT', 'type-root'];
    if (i === total - 1) return ['ANSWER', 'type-answer'];
    const z = (hops[i].zone || '').split('.').filter(Boolean);
    return z.length <= 1 ? ['TLD', 'type-tld'] : ['AUTH', 'type-auth'];
  }

  // Tabs Lista / Mapa 2D / Mapa 3D — todas ativas
  const tabsHtml = `
    <div class="trace-tabs" role="tablist">
      <button class="trace-tab trace-tab-active" data-tab="list" role="tab" aria-selected="true">Lista</button>
      <button class="trace-tab" data-tab="map2d" role="tab" aria-selected="false">Mapa 2D</button>
      <button class="trace-tab" data-tab="map3d" role="tab" aria-selected="false">Mapa 3D</button>
    </div>`;

  // Source node — fica dentro do panel "list"
  let html = `<div class="trace-area">${untrustedBanner()}${qSumHtml}${tabsHtml}`;
  html += `<div class="trace-tab-panel" data-panel="list"><div class="trace-path">`;
  html += `
    <div class="trace-node trace-node-source">
      <div class="trace-node-header">
        <span class="trace-hop-type type-source">SOURCE</span>
      </div>
      <div class="trace-server-line">
        <span class="trace-ip">${esc(data.source_hostname || traceHostname || '?')}</span>
      </div>
      <div class="trace-geo-line">
        <span class="trace-city">resolvendo via @${esc(data.resolver || '127.0.0.1')}</span>
      </div>
    </div>`;

  // Hops
  hops.forEach((hop, i) => {
    const [typeLbl, typeCls] = hopType(i, hops.length);
    const geo = geoMap[hop.server_ip] || null;
    const geoHtml = geo
      ? `<span class="trace-flag">${countryFlag(geo.countryCode)}</span>
         <span class="trace-city">${esc(geo.city || '')}${geo.city && geo.countryCode ? ', ' : ''}${esc(geo.countryCode || '')}</span>
         <span class="trace-isp">${esc(geo.isp || geo.org || '')}</span>`
      : `<span class="trace-geo-loading">—</span>`;

    const latMs = hop.latency_ms ?? null;
    let latCls = 'lat-mid';
    if (latMs != null) {
      if (latMs < 20)       latCls = 'lat-fast';
      else if (latMs < 100) latCls = 'lat-mid';
      else if (latMs < 300) latCls = 'lat-slow';
      else                  latCls = 'lat-dead';
    }
    const latBadge = latMs != null
      ? `<span class="trace-latency ${latCls}">${latMs}ms</span>` : '';

    const connMs = latMs != null ? `${latMs}ms` : '';
    html += `
    <div class="trace-connector">
      <div class="trace-connector-line"></div>
      <span class="trace-connector-arrow">▼</span>
      ${connMs ? `<span class="trace-connector-ms">${connMs}</span>` : ''}
      <div class="trace-connector-line"></div>
    </div>
    <div class="trace-node trace-node-hop">
      <div class="trace-node-header">
        <span class="trace-hop-num">${i + 1}</span>
        <span class="trace-hop-zone">${esc(hop.zone || '?')}</span>
        <span class="trace-hop-type ${typeCls}">${typeLbl}</span>
      </div>
      <div class="trace-server-line">
        <span class="trace-ip">${esc(hop.server_ip)}</span>
        ${hop.server_name && hop.server_name !== hop.server_ip
          ? `<span class="trace-name">(${esc(hop.server_name)})</span>` : ''}
      </div>
      <div class="trace-geo-line">
        ${geoHtml}
        ${latBadge}
      </div>
      ${hop.a_records && hop.a_records.length
        ? buildAnswerIps(hop.a_records, geoMap, true) : ''}
    </div>`;
  });

  // Final answer IPs (from query)
  const finalIps = (q.answers || []).map(a => a.value);
  if (finalIps.length) {
    html += `
    <div class="trace-connector">
      <div class="trace-connector-line"></div>
      <span class="trace-connector-arrow">▼</span>
      <div class="trace-connector-line"></div>
    </div>
    <div class="trace-node trace-node-answer">
      <div class="trace-node-header">
        <span class="trace-hop-type type-answer">DESTINO FINAL</span>
        <span class="trace-hop-zone">${esc(data.domain || '')}</span>
      </div>
      ${buildAnswerIps(finalIps, geoMap, false)}
    </div>`;
  }

  html += `</div></div>`;  // fecha .trace-path e panel "list"

  // Panel "map2d" — container vazio; Leaflet renderiza no click da aba
  const legendHtml = `
    <div class="trace-map-legend">
      <span><i class="trace-legend-dot" style="background:#9ece6a"></i>&lt;50ms</span>
      <span><i class="trace-legend-dot" style="background:#7aa2f7"></i>&lt;200ms</span>
      <span><i class="trace-legend-dot" style="background:#e0af68"></i>&lt;500ms</span>
      <span><i class="trace-legend-dot" style="background:#f7768e"></i>&ge;500ms</span>
      <span class="trace-map-hint">Hover pra ver detalhes</span>
    </div>`;

  html += `
    <div class="trace-tab-panel" data-panel="map2d" style="display:none">
      <div class="trace-map-container" id="trace-map-2d"></div>
      ${legendHtml}
    </div>
    <div class="trace-tab-panel" data-panel="map3d" style="display:none">
      <div class="trace-map-container trace-map-container-3d" id="trace-map-3d"></div>
      ${legendHtml.replace('Hover pra ver detalhes', 'Arraste pra rotacionar &middot; scroll pra zoom')}
    </div>`;

  html += `</div>`;  // fecha .trace-area
  return html;
}

function buildAnswerIps(ips, geoMap, compact) {
  return `<div class="trace-answer-ips">` +
    ips.map(ip => {
      const geo = geoMap[ip] || null;
      const geoTxt = geo
        ? `${countryFlag(geo.countryCode)} ${geo.city || ''}${geo.city && geo.countryCode ? ', ' : ''}${geo.countryCode || ''} — ${geo.isp || geo.org || ''}`
        : '';
      return `<div class="trace-answer-ip-row">
        <span class="trace-ip">${esc(ip)}</span>
        ${geoTxt ? `<span class="trace-geo-line" style="flex:1">${esc(geoTxt)}</span>` : `<span class="trace-geo-loading">—</span>`}
      </div>`;
    }).join('') +
  `</div>`;
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
    );
  } catch (_) { return '🌐'; }
}

async function fetchGeo(ips) {
  if (!ips.length) return {};
  const data = await apiFetch('/tools/geolocate', {
    method: 'POST',
    body: JSON.stringify({ ips }),
  });
  const map = {};
  for (const item of data) {
    if (item.query) map[item.query] = item;
  }
  return map;
}

// Event-bus wrapper: <span data-action="showResultModalEv" data-result="<encoded>">
// Le e decodifica raw result string + delega pra showResultModal real.
function showResultModalEv(e) {
  const raw = e.currentTarget.dataset.result;
  if (!raw) return;
  try {
    showResultModal(decodeURIComponent(raw));
  } catch (_) {
    showResultModal(raw);  // fallback se decode falhar
  }
}

// Event-bus wrapper pro select de resolver: dispatcher chama na change,
// helper original espera ouvir 'this.value'.
// (admin-commands.js define um `change` listener inline que checava
// `this.value === 'custom'`. Ja eh addEventListener — sem mudanca aqui.)
