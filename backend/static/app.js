/* ===========================================================================
   app.js — Utilitarios compartilhados (login, admin, dashboard)
   =========================================================================== */

const API_BASE = '/api/v1';

// ── Token ──
function token() {
  if (window.__TOKEN__) return window.__TOKEN__;
  const el = document.getElementById('tokenInput') || document.getElementById('token-input');
  return el ? el.value.trim() : '';
}

// ── API fetch ──
async function apiFetch(path, opts = {}) {
  const t = token();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (t) headers['Authorization'] = 'Bearer ' + t;
  const resp = await fetch(API_BASE + path, { ...opts, headers });
  if (!resp.ok) {
    let detail = resp.status + ' ' + resp.statusText;
    try { const body = await resp.json(); if (body.detail) detail = body.detail; } catch (_) {}
    throw new ApiError(detail, resp.status);
  }
  return resp.json();
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
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

// ── SVG icons (inline, 16x16) ──
const ICONS = {
  success: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M5 8.5l2 2 4-4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  error:   '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M6 6l4 4M10 6l-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  warning: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2L1.5 13.5h13L8 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 7v3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="12" r=".8" fill="currentColor"/></svg>',
  info:    '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M8 7v4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="5" r=".8" fill="currentColor"/></svg>',
  loading: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" class="spin"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.5" opacity=".25"/><path d="M14.5 8a6.5 6.5 0 00-6.5-6.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
};

// ── Toast system ──
// Tipos: 'success' | 'error' | 'warning' | 'info'
// Atalhos: toast.ok(msg), toast.err(msg), toast.warn(msg), toast.info(msg)
function toast(msg, typeOrBool, duration) {
  let type;
  if (typeof typeOrBool === 'boolean') type = typeOrBool ? 'success' : 'error';
  else type = typeOrBool || 'success';

  const dur = duration || (type === 'error' ? 5000 : 3500);
  const colors = { success: 'var(--green)', error: 'var(--red)', warning: 'var(--yellow)', info: 'var(--accent)' };
  const color = colors[type] || colors.info;

  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.innerHTML = '<span class="toast-icon">' + (ICONS[type] || '') + '</span>'
    + '<span class="toast-msg">' + esc(msg) + '</span>'
    + '<button class="toast-close" onclick="this.parentElement.remove()">&times;</button>';

  container.appendChild(el);
  // Trigger reflow for animation
  el.offsetHeight;
  el.classList.add('toast-visible');

  const timer = setTimeout(() => dismissToast(el), dur);
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', () => setTimeout(() => dismissToast(el), 1500));
}

function dismissToast(el) {
  if (!el || !el.parentElement) return;
  el.classList.remove('toast-visible');
  el.classList.add('toast-exit');
  setTimeout(() => el.remove(), 300);
}

// Atalhos
toast.ok   = (msg, dur) => toast(msg, 'success', dur);
toast.err  = (msg, dur) => toast(msg, 'error', dur);
toast.warn = (msg, dur) => toast(msg, 'warning', dur);
toast.info = (msg, dur) => toast(msg, 'info', dur);

// ── Inline error/empty/loading helpers ──
function showInlineError(selector, msg, code) {
  const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
  if (!el) return;
  const codeHint = code ? ' <span class="dim">(' + code + ')</span>' : '';
  el.innerHTML = '<div class="inline-msg inline-error fade-in">'
    + '<span class="inline-msg-icon">' + ICONS.error + '</span>'
    + '<div><strong>Erro</strong><p>' + esc(msg) + codeHint + '</p></div>'
    + '</div>';
}

function showInlineEmpty(selector, msg) {
  const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
  if (!el) return;
  el.innerHTML = '<div class="inline-msg inline-empty fade-in">'
    + '<span class="inline-msg-icon">' + ICONS.info + '</span>'
    + '<p>' + esc(msg || 'Nenhum dado encontrado.') + '</p></div>';
}

function showInlineLoading(selector, msg) {
  const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
  if (!el) return;
  el.innerHTML = '<div class="inline-msg inline-loading">'
    + '<span class="inline-msg-icon">' + ICONS.loading + '</span>'
    + '<p>' + esc(msg || 'Carregando...') + '</p></div>';
}

// ── Button loading state ──
function btnLoading(btn, loading) {
  if (loading) {
    btn.dataset.origText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = ICONS.loading + ' <span>Aguarde...</span>';
    btn.classList.add('btn-loading');
  } else {
    btn.disabled = false;
    btn.innerHTML = btn.dataset.origText || btn.innerHTML;
    btn.classList.remove('btn-loading');
  }
}

// ── Page transition ──
document.addEventListener('DOMContentLoaded', () => {
  document.body.style.opacity = '0';
  document.body.style.transition = 'opacity .3s ease';
  requestAnimationFrame(() => { document.body.style.opacity = '1'; });
});
