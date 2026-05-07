/**
 * event-bus.js — Dispatcher global pra event delegation.
 *
 * Substitui handlers inline (onclick/onchange/onsubmit) por delegacao
 * usando data-action attribute. Permite remover 'unsafe-inline' do CSP
 * (Onda B/CSP refactor B, 2026-05-06).
 *
 * Pattern de uso:
 *
 *   // Sem argumento:
 *   <button data-action="closeModal">FECHAR</button>
 *
 *   // Com arg via data-* (function le do event.currentTarget.dataset):
 *   <th data-action="sortAgents" data-field="hostname">Hostname</th>
 *   ...
 *   window.sortAgents = (e) => {
 *     const field = e.currentTarget.dataset.field;
 *     ...
 *   };
 *
 *   // Form submit:
 *   <form data-action-submit="saveClient">...</form>
 *
 *   // Change handler:
 *   <select data-action-change="onTraceResolverChange">...</select>
 *
 * Funcao apontada DEVE estar em window.<name>. Se nao existir, dispatcher
 * loga warn (uma vez) — facilita debug em DEV sem poluir.
 *
 * .closest() permite click em filho — o dispatcher acha o elemento com
 * data-action mais proximo (importante quando o button tem icon span dentro).
 */

(function () {
  'use strict';
  if (window.__eventBusInstalled) return;
  window.__eventBusInstalled = true;

  const _warned = new Set();
  function _warn(name) {
    if (_warned.has(name)) return;
    _warned.add(name);
    console.warn('[event-bus] handler nao encontrado:', name);
  }

  function _dispatch(eventType, attr) {
    document.addEventListener(eventType, (e) => {
      const el = e.target.closest('[' + attr + ']');
      if (!el) return;
      const name = el.getAttribute(attr);
      if (!name) return;
      const fn = window[name];
      if (typeof fn !== 'function') {
        _warn(name);
        return;
      }
      // Forca currentTarget = elemento que tem data-action
      // (e.target pode ser filho — span, icon, etc)
      Object.defineProperty(e, 'currentTarget', { value: el, configurable: true });
      try {
        fn.call(el, e);
      } catch (err) {
        console.error('[event-bus] erro em', name, ':', err);
      }
    }, true);  // capture=true pra rodar antes de eventos do framework
  }

  _dispatch('click',  'data-action');
  _dispatch('change', 'data-action-change');
  _dispatch('submit', 'data-action-submit');
  _dispatch('input',  'data-action-input');
})();
