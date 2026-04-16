/* ===========================================================================
   app.js — Utilitarios compartilhados (login, admin, dashboard)
   =========================================================================== */

const API_BASE = '/api/v1';

// ── Token ──
function token() {
  const el = document.getElementById('tokenInput') || document.getElementById('token-input');
  return el ? el.value.trim() : '';
}

// ── API fetch ──
async function apiFetch(path, opts = {}) {
  const t = token();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (t) headers['Authorization'] = 'Bearer ' + t;
  const resp = await fetch(API_BASE + path, { ...opts, headers });
  if (!resp.ok) throw new Error(resp.status + ' ' + resp.statusText);
  return resp.json();
}

// ── Formatters ──
function fmtDate(iso) {
  if (!iso) return '<span class="dim">\u2014</span>';
  return new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

function fmtTime(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

function fmtAgo(iso) {
  if (!iso) return '';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'min';
  if (s < 86400)return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}

// ── XSS escape ──
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Stagger animations ──
function animateChildren(selector, animClass) {
  const parent = document.querySelector(selector);
  if (!parent) return;
  Array.from(parent.children).forEach((el, i) => {
    el.classList.add(animClass || 'fade-in');
    el.style.animationDelay = (i * 0.06) + 's';
  });
}

// ── Toast notifications ──
function toast(msg, ok = true, duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    Object.assign(container.style, {
      position: 'fixed', bottom: '24px', right: '24px',
      display: 'flex', flexDirection: 'column', gap: '8px',
      zIndex: '9999', pointerEvents: 'none',
    });
    document.body.appendChild(container);
  }
  const t = document.createElement('div');
  Object.assign(t.style, {
    background: 'var(--bg-card)', border: '1px solid ' + (ok ? 'var(--green)' : 'var(--red)'),
    borderRadius: '8px', padding: '10px 18px', color: ok ? 'var(--green)' : 'var(--red)',
    fontFamily: 'var(--font-mono)', fontSize: '12px', pointerEvents: 'auto',
    animation: 'slideUp .3s ease both', maxWidth: '400px', wordBreak: 'break-word',
  });
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, duration);
}

// ── Page transition ──
document.addEventListener('DOMContentLoaded', () => {
  document.body.style.opacity = '0';
  document.body.style.transition = 'opacity .3s ease';
  requestAnimationFrame(() => { document.body.style.opacity = '1'; });
});
