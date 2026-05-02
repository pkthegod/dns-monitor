// admin-agents.js — extraido de admin.html (Fase B2 do refactor)
// Estado compartilhado, helpers de UI, CRUD/menu/bulk de agentes.
// Carregado em <script src="..."> antes de admin-commands.js e admin-clients.js.

const REFRESH_INTERVAL = 300;
let editingHostname = null;
let diagHostname    = null;
let diagPollTimer   = null;
let serverVersion   = null;

// -- Countdown ------------------------------------------------------------
let remaining = REFRESH_INTERVAL;
function updateCountdown() {
  const m = String(Math.floor(remaining / 60)).padStart(1, '0');
  const s = String(remaining % 60).padStart(2, '0');
  document.getElementById('countdown').textContent = `${m}:${s}`;
  remaining--;
  if (remaining < 0) { remaining = REFRESH_INTERVAL; loadAll(); }
}
setInterval(updateCountdown, 1000);

// -- Helpers --------------------------------------------------------------
function statusPill(s) {
  const map = {
    online:     ['online',  'Online'],
    stale:      ['stale',   'Instável'],
    offline:    ['offline', 'Offline'],
    never_seen: ['never',   'Nunca visto'],
  };
  const [cls, label] = map[s] || ['never', s];
  return `<span class="pill pill-${cls}">${label}</span>`;
}

function activePill(v) {
  if (v === true)  return '<span class="pill pill-active">Ativo</span>';
  if (v === false) return '<span class="pill pill-inactive">Inativo</span>';
  return '<span class="dim">—</span>';
}

function metricCell(val, warnAt, critAt) {
  if (val == null) return '<span class="dim">—</span>';
  const n = parseFloat(val).toFixed(1);
  let cls = 'metric-ok';
  if (val >= critAt)      cls = 'metric-crit';
  else if (val >= warnAt) cls = 'metric-warn';
  return `<span class="metric ${cls}">${n}%</span>`;
}

// Compara duas versoes semver. Retorna 'equal' | 'patch' | 'minor' | 'major' | 'ahead' | 'unknown'
// 'patch'/'minor'/'major' significa LOCAL atras do REMOTO; 'ahead' = local na frente.
function _semverDiff(local, remote) {
  if (!local || !remote) return 'unknown';
  if (local === remote) return 'equal';
  const lp = local.split('.').map(Number);
  const rp = remote.split('.').map(Number);
  while (lp.length < 3) lp.push(0);
  while (rp.length < 3) rp.push(0);
  if (lp.some(isNaN) || rp.some(isNaN)) return 'unknown';
  if (lp[0] !== rp[0]) return lp[0] < rp[0] ? 'major' : 'ahead';
  if (lp[1] !== rp[1]) return lp[1] < rp[1] ? 'minor' : 'ahead';
  if (lp[2] !== rp[2]) return lp[2] < rp[2] ? 'patch' : 'ahead';
  return 'equal';
}

function isOutdated(agentVer) {
  if (!agentVer || !serverVersion) return false;
  const d = _semverDiff(agentVer, serverVersion);
  return d === 'patch' || d === 'minor' || d === 'major';
}
// Alias mantido pra retrocompat com chamadas internas que usavam underscore.
const _isOutdated = isOutdated;

function versionCell(agentVer) {
  if (!agentVer) return '<span class="dim">—</span>';
  // serverVersion ainda nao carregou (ou /agent/version falhou): badge amarelo
  // com "?" pra deixar visivel que falta info — antes ficava cinza silencioso.
  if (!serverVersion) {
    return `<span class="version-badge version-old-minor" title="Servidor nao respondeu /agent/version — abra DevTools console pra detalhes">${esc(agentVer)} ?</span>`;
  }
  const diff = _semverDiff(agentVer, serverVersion);
  if (diff === 'equal') return `<span class="version-badge version-ok">${esc(agentVer)}</span>`;
  if (diff === 'ahead') return `<span class="version-badge version-ahead" title="Agente esta a frente do servidor (server: ${esc(serverVersion)})">${esc(agentVer)} ↑dev</span>`;
  if (diff === 'unknown') return `<span class="version-badge version-unknown">${esc(agentVer)}</span>`;
  const cls = diff === 'major' ? 'version-old-major' : diff === 'minor' ? 'version-old-minor' : 'version-old-patch';
  const label = diff === 'major' ? 'BREAKING' : diff === 'minor' ? 'UPDATE' : 'PATCH';
  return `<span class="version-badge ${cls}" title="${label} disponivel. Servidor: ${esc(serverVersion)}. Clique Update no menu do agente.">${esc(agentVer)} → ${esc(serverVersion)}</span>`;
}

function refreshOutdatedBadge() {
  const badge = document.getElementById('outdated-badge');
  if (!badge) return;
  if (!serverVersion || !agentsCache.length) { badge.style.display = 'none'; return; }
  const outdated = agentsCache.filter(a => _isOutdated(a.agent_version));
  if (!outdated.length) { badge.style.display = 'none'; return; }
  const breaking = outdated.filter(a => _semverDiff(a.agent_version, serverVersion) === 'major').length;
  badge.style.display = 'inline-flex';
  badge.textContent = `${outdated.length} de ${agentsCache.length} desatualizado(s)` + (breaking ? ` · ${breaking} breaking` : '');
  badge.className = 'version-badge ' + (breaking > 0 ? 'version-old-major' : 'version-old-minor');
}

// -- Send command ---------------------------------------------------------
async function sendCommand(hostname, command, btn) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  if (command === 'disable') {
    if (!confirm(`Desabilitar o serviço DNS em "${hostname}"?\nO serviço não iniciará no boot.`)) return;
  }
  if (btn) btn.disabled = true;
  try {
    await apiFetch('/commands', {
      method: 'POST',
      body: JSON.stringify({ hostname, command, issued_by: 'admin-panel' }),
    });
    toast(`"${command.toUpperCase()}" enfileirado para ${hostname}.`);
    await loadHistory();
  } catch (e) {
    toast.err(e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// -- Delete agent ---------------------------------------------------------
async function deleteAgent(hostname, btn) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  if (!confirm(`Remover "${hostname}" do banco de dados?\n\nTodos os dados históricos serão apagados permanentemente.`)) return;
  if (!confirm(`Confirmar remoção definitiva de "${hostname}"?`)) return;
  if (btn) btn.disabled = true;
  try {
    await apiFetch(`/agents/${encodeURIComponent(hostname)}`, { method: 'DELETE' });
    toast(`Agente "${hostname}" removido.`);
    await loadAgents();
  } catch (e) {
    toast.err('Erro ao remover: ' + e.message);
    if (btn) btn.disabled = false;
  }
}

// -- Edit modal -----------------------------------------------------------
let agentsCache = [];

function openEditModal(hostname) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  editingHostname = hostname;
  const a = agentsCache.find(x => x.hostname === hostname) || {};
  document.getElementById('modal-title').textContent = `EDITAR — ${hostname}`;
  document.getElementById('edit-display-name').value = a.display_name || '';
  document.getElementById('edit-location').value     = a.location     || '';
  document.getElementById('edit-notes').value        = a.notes        || '';
  const isActive = a.active !== false;
  const cb = document.getElementById('edit-active');
  cb.checked = isActive;
  document.getElementById('edit-active-label').textContent = isActive ? 'Ativo' : 'Inativo';
  document.getElementById('edit-inactive-warning').style.display = isActive ? 'none' : 'block';
  document.getElementById('edit-modal').classList.add('open');
  document.getElementById('edit-display-name').focus();
}

function closeEditModal() {
  document.getElementById('edit-modal').classList.remove('open');
  editingHostname = null;
}

document.getElementById('edit-active').addEventListener('change', function() {
  document.getElementById('edit-active-label').textContent = this.checked ? 'Ativo' : 'Inativo';
  document.getElementById('edit-inactive-warning').style.display = this.checked ? 'none' : 'block';
});

async function saveEdit() {
  if (!editingHostname) return;
  const active = document.getElementById('edit-active').checked;
  const a = agentsCache.find(x => x.hostname === editingHostname) || {};
  if (!active && a.active !== false) {
    if (!confirm(`Marcar "${editingHostname}" como inativo?\n\nO agente será removido automaticamente em 3 dias se não for reativado.`)) return;
  }
  const body = {
    display_name: document.getElementById('edit-display-name').value.trim() || null,
    location:     document.getElementById('edit-location').value.trim()     || null,
    notes:        document.getElementById('edit-notes').value.trim()        || null,
    active,
  };
  try {
    await apiFetch(`/agents/${encodeURIComponent(editingHostname)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    });
    toast(`Dados de "${editingHostname}" salvos.`);
    closeEditModal();
    await loadAgents();
  } catch (e) {
    toast.err('Erro ao salvar: ' + e.message);
  }
}

document.getElementById('edit-modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeEditModal();
});

// -- Agent action menu ----------------------------------------------------
let _menuTrigger = null;

function openAgentMenu(event, hostname, agentVersion, displayName) {
  event.stopPropagation();
  const trigger  = event.currentTarget;
  const menu     = document.getElementById('agent-menu');
  const outdated = isOutdated(agentVersion);
  const label    = displayName || hostname;

  // Toggle: fechar se já está aberto para este trigger
  if (_menuTrigger === trigger && menu.classList.contains('open')) {
    closeAgentMenu(); return;
  }
  if (_menuTrigger) closeAgentMenu();
  _menuTrigger = trigger;
  trigger.classList.add('active');

  // -- Montar itens -------------------------------------------------------
  const updateBadge = outdated
    ? `<span class="menu-badge" style="background:#2a1e0a;color:var(--yellow);border:1px solid #5a3d10">${esc(agentVersion||'?')} → ${esc(serverVersion||'?')}</span>`
    : '';

  menu.innerHTML = `
    <div class="menu-header">
      <div class="menu-header-hostname">${esc(label)}</div>
      ${displayName && displayName !== hostname ? `<div class="menu-header-sub">${esc(hostname)}</div>` : ''}
    </div>

    <div class="menu-group-label">Serviço DNS</div>
    <div class="menu-item mi-restart" onclick="_menuAction(()=>sendCommand('${esc(hostname)}','restart',null))">
      <span class="menu-icon">↺</span><span class="menu-label">Restart</span>
    </div>
    <div class="menu-item mi-enable"  onclick="_menuAction(()=>sendCommand('${esc(hostname)}','enable',null))">
      <span class="menu-icon">◉</span><span class="menu-label">Enable</span>
    </div>
    <div class="menu-item mi-disable" onclick="_menuAction(()=>sendCommand('${esc(hostname)}','disable',null))">
      <span class="menu-icon">○</span><span class="menu-label">Disable</span>
    </div>

    <div class="menu-divider"></div>
    <div class="menu-group-label">Diagnóstico</div>
    <div class="menu-item mi-diag"  onclick="_menuAction(()=>openDiagModal('${esc(hostname)}'))">
      <span class="menu-icon">⬡</span><span class="menu-label">Validar serviço</span>
    </div>
    <div class="menu-item mi-trace" onclick="_menuAction(()=>openTraceModal('${esc(hostname)}'))">
      <span class="menu-icon">⊕</span><span class="menu-label">DNS Trace</span>
    </div>

    <div class="menu-divider"></div>
    <div class="menu-group-label">Agente</div>
    ${outdated ? `
    <div class="menu-item mi-update" onclick="_menuAction(()=>sendUpdate('${esc(hostname)}',null))">
      <span class="menu-icon">↑</span><span class="menu-label">Atualizar</span>${updateBadge}
    </div>` : ''}
    <div class="menu-item mi-edit"   onclick="_menuAction(()=>openEditModal('${esc(hostname)}'))">
      <span class="menu-icon">✎</span><span class="menu-label">Editar</span>
    </div>
    <div class="menu-item mi-delete" onclick="_menuAction(()=>deleteAgent('${esc(hostname)}',null))">
      <span class="menu-icon">⊗</span><span class="menu-label">Deletar</span>
    </div>
  `;

  // -- Posicionar ---------------------------------------------------------
  menu.classList.add('open');
  const rect   = trigger.getBoundingClientRect();
  const mw     = menu.offsetWidth  || 220;
  const mh     = menu.offsetHeight || 280;
  const vw     = window.innerWidth;
  const vh     = window.innerHeight;
  const gap    = 6;

  // Horizontal: alinhar à direita do trigger, garantir que não saia da tela
  let left = rect.right - mw;
  if (left < 8) left = 8;
  if (left + mw > vw - 8) left = vw - mw - 8;

  // Vertical: abrir para baixo se couber, senão para cima
  let top;
  if (rect.bottom + gap + mh <= vh) {
    top = rect.bottom + gap;
  } else {
    top = rect.top - gap - mh;
    if (top < 8) top = rect.bottom + gap; // fallback se também não couber acima
  }

  menu.style.left = `${left}px`;
  menu.style.top  = `${top}px`;
}

function _menuAction(fn) {
  closeAgentMenu();
  fn();
}

function closeAgentMenu() {
  const menu = document.getElementById('agent-menu');
  menu.classList.remove('open');
  if (_menuTrigger) { _menuTrigger.classList.remove('active'); _menuTrigger = null; }
}

// Fechar ao clicar fora ou pressionar ESC
document.addEventListener('click', e => {
  const menu = document.getElementById('agent-menu');
  if (menu.classList.contains('open') && !menu.contains(e.target)) {
    closeAgentMenu();
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeAgentMenu();
});

// -- Agent update ---------------------------------------------------------
async function fetchServerVersion() {
  if (!whoami()) return;
  try {
    const data = await apiFetch('/agent/version');
    serverVersion = data.version || null;
    if (!serverVersion) {
      console.warn('[infra-vision] /agent/version sem campo version no response');
    }
  } catch (e) {
    serverVersion = null;
    console.warn('[infra-vision] /agent/version falhou:', e?.message || e,
      '— badges de versao ficarao em modo "?" ate restaurar.');
  }
  // Race-fix: fetchServerVersion roda em paralelo com loadAgents via Promise.all.
  // Se a tabela ja foi renderizada com serverVersion=null, todos badges ficam
  // 'version-unknown' (cinza) ate o proximo refresh. Forca re-render aqui.
  if (Array.isArray(agentsCache) && agentsCache.length > 0) {
    renderAgentRows(agentsCache);
  } else {
    refreshOutdatedBadge();
  }
}

async function sendUpdate(hostname, btn) {
  if (!canWrite()) { toast.warn('Permissao insuficiente. Requer role admin.'); return; }
  if (!confirm(
    `Atualizar agente em "${hostname}"?\n\n` +
    `Versão atual do servidor: ${serverVersion || '?'}\n\n` +
    `O agente baixará o novo arquivo, verificará o checksum e reiniciará automaticamente.`
  )) return;
  if (btn) btn.disabled = true;
  try {
    await apiFetch('/commands', {
      method: 'POST',
      body: JSON.stringify({ hostname, command: 'update_agent', issued_by: 'admin-panel' }),
    });
    toast(`UPDATE enfileirado para ${hostname}. Aguarde o próximo poll do agente.`);
    await loadHistory();
  } catch (e) {
    toast.err(e.message);
    if (btn) btn.disabled = false;
  }
}

// -- Load agents ----------------------------------------------------------
async function loadAgents() {
  const tbody = document.getElementById('tbody-agents');
  try {
    const agents = await apiFetch('/agents');
    agentsCache = agents;
    document.getElementById('badge-agents').textContent =
      `${agents.filter(a => a.agent_status === 'online').length} online / ${agents.length} total`;

    if (!agents.length) {
      tbody.innerHTML = '<tr><td colspan="12" class="dim" style="padding:14px">Nenhum agente registrado.</td></tr>';
      return;
    }

    renderAgentRows(agents);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="12"><div class="inline-msg inline-error fade-in"><span class="inline-msg-icon">${ICONS.error}</span><div><strong>Erro ao carregar agentes</strong><p>${esc(e.message)}</p></div></div></td></tr>`;
  }
}

let _sortField = 'hostname', _sortAsc = true;
function sortAgents(field) {
  if (_sortField === field) _sortAsc = !_sortAsc;
  else { _sortField = field; _sortAsc = true; }
  renderAgentRows(agentsCache);
}

function renderAgentRows(agents) {
  const tbody = document.getElementById('tbody-agents');
  const search = (document.getElementById('agentSearch')?.value || '').toLowerCase();
  const statusF = document.getElementById('statusFilter')?.value || '';

  let filtered = agents.filter(a => {
    if (search && !a.hostname.toLowerCase().includes(search)) return false;
    if (statusF && a.agent_status !== statusF) return false;
    return true;
  });

  filtered.sort((a, b) => {
    let va = a[_sortField], vb = b[_sortField];
    if (va == null) va = ''; if (vb == null) vb = '';
    if (typeof va === 'number' && typeof vb === 'number') return _sortAsc ? va - vb : vb - va;
    return _sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
  });

  document.getElementById('badge-agents').textContent =
    `${filtered.filter(a=>a.agent_status==='online').length} online / ${filtered.length}${filtered.length !== agents.length ? ' de ' + agents.length : ''} total`;

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="12" class="dim" style="padding:14px">Nenhum agente encontrado.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(a => {
      const isActive = a.active !== false;
      const purgeDate = a.inactive_since
        ? new Date(new Date(a.inactive_since).getTime() + 3 * 86400000) : null;
      const daysLeft = purgeDate ? Math.ceil((purgeDate - Date.now()) / 86400000) : null;
      const clientCell = isActive
        ? '<span class="pill pill-client-active">Ativo</span>'
        : `<span class="pill pill-client-inactive">Inativo</span>${daysLeft !== null ? `<div class="purge-warning">apaga em ${daysLeft}d</div>` : ''}`;
      const statusBorder = {online:'var(--green)',stale:'var(--yellow)',offline:'var(--red)',never_seen:'var(--text-dim)'}[a.agent_status] || 'var(--border)';

      return `
      <tr style="border-left:3px solid ${statusBorder}${isActive ? '' : ';opacity:.55'}">
        <td><input type="checkbox" class="bulk-cb" data-hostname="${esc(a.hostname)}" onchange="bulkUpdateCount()"></td>
        <td>
          <strong>${esc(a.hostname)}</strong>
          ${a.display_name && a.display_name !== a.hostname ? `<br><span class="dim">${esc(a.display_name)}</span>` : ''}
        </td>
        <td><span class="dim">${esc(a.location) || '—'}</span></td>
        <td>${clientCell}</td>
        <td>${statusPill(a.agent_status)}</td>
        <td>${metricCell(a.cpu_percent, 80, 95)}</td>
        <td>${metricCell(a.ram_percent, 85, 95)}</td>
        <td><span class="dim">${esc(a.dns_service_name) || '—'}</span></td>
        <td>${activePill(a.dns_service_active)}</td>
        <td>${versionCell(a.agent_version)}</td>
        <td><span class="dim">${fmtDate(a.last_seen)}</span></td>
        <td>
          <button class="agent-menu-trigger"
            onclick="openAgentMenu(event,'${esc(a.hostname)}','${esc(a.agent_version||'')}','${esc(a.display_name||'')}')">
            ⋯
          </button>
        </td>
      </tr>`;
    }).join('');
  refreshOutdatedBadge();
}

// -- Bulk actions ---------------------------------------------------------
function getSelectedHostnames() {
  return [...document.querySelectorAll('.bulk-cb:checked')].map(cb => cb.dataset.hostname);
}

function bulkUpdateCount() {
  const selected = getSelectedHostnames();
  const bar = document.getElementById('bulk-bar');
  const count = document.getElementById('bulk-count');
  if (selected.length > 0) {
    bar.style.display = 'flex';
    count.textContent = selected.length + ' selecionado' + (selected.length > 1 ? 's' : '');
  } else {
    bar.style.display = 'none';
  }
}

function bulkToggleAll(checked) {
  document.querySelectorAll('.bulk-cb').forEach(cb => { cb.checked = checked; });
  bulkUpdateCount();
}

function bulkSelectOffline() {
  document.querySelectorAll('.bulk-cb').forEach(cb => { cb.checked = false; });
  const offlineHosts = agentsCache.filter(a => a.agent_status === 'offline').map(a => a.hostname);
  document.querySelectorAll('.bulk-cb').forEach(cb => {
    if (offlineHosts.includes(cb.dataset.hostname)) cb.checked = true;
  });
  bulkUpdateCount();
  if (!getSelectedHostnames().length) toast.info('Nenhum agente offline encontrado.');
}

function bulkSelectOutdated() {
  document.querySelectorAll('.bulk-cb').forEach(cb => { cb.checked = false; });
  if (!serverVersion) { toast.warn('Versao do servidor nao carregada ainda — recarregue a pagina.'); return; }
  const outdatedHosts = agentsCache.filter(a => _isOutdated(a.agent_version)).map(a => a.hostname);
  document.querySelectorAll('.bulk-cb').forEach(cb => {
    if (outdatedHosts.includes(cb.dataset.hostname)) cb.checked = true;
  });
  bulkUpdateCount();
  if (!getSelectedHostnames().length) toast.info('Todos os agentes estao na versao atual.');
  else toast.ok(`${outdatedHosts.length} agente(s) desatualizado(s) selecionado(s). Clique "Update" pra disparar.`);
}

async function bulkAction(command) {
  const hostnames = getSelectedHostnames();
  if (!hostnames.length) { toast.warn('Selecione ao menos um agente.'); return; }
  const label = command === 'update_agent' ? 'atualizar' : command;
  if (!confirm(`Executar "${label}" em ${hostnames.length} agente(s)?\n\n${hostnames.join(', ')}`)) return;
  if (command === 'decommission' && !confirm('CONFIRMAR decommission? Essa acao desinstala o agente das maquinas.')) return;

  let ok = 0, fail = 0;
  for (const hostname of hostnames) {
    try {
      await apiFetch('/commands', {
        method: 'POST',
        body: JSON.stringify({ hostname, command, issued_by: 'admin-bulk' }),
      });
      ok++;
    } catch (_) { fail++; }
  }
  if (ok) toast.ok(`${ok} comando(s) "${label}" enfileirado(s).`);
  if (fail) toast.err(`${fail} falha(s) ao enviar.`);
  document.getElementById('bulk-select-all').checked = false;
  bulkToggleAll(false);
  await loadHistory();
}
