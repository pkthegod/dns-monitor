// admin-clients.js — extraido de admin.html (Fase B2 do refactor)
// CRUD de Clientes (portal read-only) e Admin Users (RBAC).
// Carregado depois de admin-agents.js e admin-commands.js no admin.html.

// -- CRUD Clientes --------------------------------------------------------
let clientsCache = [];
let editingClientId = null;

async function loadClients() {
  const tbody = document.getElementById('tbody-clients');
  try {
    const clients = await apiFetch('/clients');
    clientsCache = clients;
    document.getElementById('badge-clients').textContent = `${clients.filter(c=>c.active).length} ativos / ${clients.length} total`;
    if (!clients.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="dim" style="padding:14px">Nenhum cliente cadastrado.</td></tr>';
      return;
    }
    tbody.innerHTML = clients.map(c => {
      const hosts = (c.hostnames || []).map(h => `<span class="pill pill-host">${esc(h)}</span>`).join(' ');
      const statusPill = c.active
        ? '<span class="pill pill-client-active">Ativo</span>'
        : '<span class="pill pill-client-inactive">Inativo</span>';
      return `<tr>
        <td><strong>${esc(c.username)}</strong></td>
        <td>${hosts || '<span class="dim">—</span>'}</td>
        <td><span class="dim">${esc(c.email || '—')}</span></td>
        <td><span class="dim">${esc(c.notes || '—')}</span></td>
        <td>${statusPill}</td>
        <td><span class="dim">${fmtDate(c.created_at)}</span></td>
        <td class="admin-only">
          <button class="btn btn-ghost" style="font-size:.7rem;padding:2px 8px" data-action="openClientModal" data-client-id="${c.id}">Editar</button>
          <button class="btn btn-ghost" style="font-size:.7rem;padding:2px 8px;color:var(--red)" data-action="deleteClient" data-client-id="${c.id}" data-username="${esc(c.username)}">Remover</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="inline-msg inline-error fade-in"><span class="inline-msg-icon">${ICONS.error}</span><div><strong>Erro ao carregar clientes</strong><p>${esc(e.message)}</p></div></div></td></tr>`;
  }
}

function openClientModal(clientIdOrEvent) {
  // Suporta:
  //   openClientModal()        — botao "+ Novo Cliente"
  //   openClientModal(123)     — callsite legacy
  //   openClientModal(event)   — dispatcher event-bus, le data-client-id
  let clientId = clientIdOrEvent;
  if (clientIdOrEvent && typeof clientIdOrEvent === 'object' && clientIdOrEvent.currentTarget) {
    const raw = clientIdOrEvent.currentTarget.dataset.clientId;
    clientId = raw ? Number(raw) : null;
  }
  editingClientId = clientId || null;
  const isEdit = !!clientId;
  document.getElementById('client-modal-title').textContent = isEdit ? 'Editar Cliente' : 'Novo Cliente';
  document.getElementById('client-save-btn').textContent = isEdit ? 'SALVAR' : 'CRIAR';
  document.getElementById('client-active-wrap').style.display = isEdit ? '' : 'none';
  document.getElementById('client-username').disabled = isEdit;

  if (isEdit) {
    const c = clientsCache.find(x => x.id === clientId) || {};
    document.getElementById('client-username').value = c.username || '';
    document.getElementById('client-password').value = '';
    document.getElementById('client-password').placeholder = 'deixe vazio para manter';
    document.getElementById('client-hostnames').value = (c.hostnames || []).join(', ');
    document.getElementById('client-domains').value = (c.domains || []).join(', ');
    document.getElementById('client-email').value = c.email || '';
    document.getElementById('client-notes').value = c.notes || '';
    document.getElementById('client-active').checked = c.active !== false;
    document.getElementById('client-active-label').textContent = c.active !== false ? 'Ativo' : 'Inativo';
  } else {
    document.getElementById('client-username').value = '';
    document.getElementById('client-password').value = '';
    document.getElementById('client-password').placeholder = 'senha de acesso';
    document.getElementById('client-hostnames').value = '';
    document.getElementById('client-domains').value = '';
    document.getElementById('client-email').value = '';
    document.getElementById('client-notes').value = '';
    document.getElementById('client-active').checked = true;
  }
  document.getElementById('client-modal').classList.add('open');
  document.getElementById(isEdit ? 'client-hostnames' : 'client-username').focus();
}

function closeClientModal() {
  document.getElementById('client-modal').classList.remove('open');
  editingClientId = null;
}

document.getElementById('client-active').addEventListener('change', function() {
  document.getElementById('client-active-label').textContent = this.checked ? 'Ativo' : 'Inativo';
});

// Event-bus wrapper: <form data-action-submit="saveClientEv">
// Previne navigation default + chama saveClient.
function saveClientEv(e) {
  if (e && e.preventDefault) e.preventDefault();
  return saveClient();
}

async function saveClient() {
  const username = document.getElementById('client-username').value.trim();
  const password = document.getElementById('client-password').value;
  const hostnamesRaw = document.getElementById('client-hostnames').value;
  const hostnames = hostnamesRaw.split(',').map(h => h.trim()).filter(Boolean);
  const domainsRaw = document.getElementById('client-domains').value;
  // Dominios speedtest sao opcionais — array vazio se campo em branco
  const domains = domainsRaw.split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
  const email = document.getElementById('client-email').value.trim();
  const notes = document.getElementById('client-notes').value.trim();

  if (!editingClientId) {
    // Criar
    if (!username || !password) { toast.err('Username e senha obrigatorios.'); return; }
    if (!hostnames.length) { toast.err('Informe ao menos um hostname.'); return; }
    try {
      await apiFetch('/clients', {
        method: 'POST',
        body: JSON.stringify({ username, password, hostnames, domains, notes, email }),
      });
      toast.ok(`Cliente "${username}" criado.`);
      closeClientModal();
      await loadClients();
    } catch (e) { toast.err(e.message); }
  } else {
    // Editar
    if (!hostnames.length) { toast.err('Informe ao menos um hostname.'); return; }
    const body = { hostnames, domains, notes, email, active: document.getElementById('client-active').checked };
    if (password) body.password = password;
    try {
      await apiFetch(`/clients/${editingClientId}`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      });
      toast.ok('Cliente atualizado.');
      closeClientModal();
      await loadClients();
    } catch (e) { toast.err(e.message); }
  }
}

async function deleteClient(clientIdOrEvent, username) {
  // dispatcher event-bus passa event; legacy passa (id, username)
  let clientId = clientIdOrEvent;
  if (clientIdOrEvent && typeof clientIdOrEvent === 'object' && clientIdOrEvent.currentTarget) {
    const ds = clientIdOrEvent.currentTarget.dataset;
    clientId = Number(ds.clientId);
    username = ds.username;
  }
  if (!confirm(`Remover o cliente "${username}"?\n\nEle perdera acesso ao portal.`)) return;
  try {
    await apiFetch(`/clients/${clientId}`, { method: 'DELETE' });
    toast.ok(`Cliente "${username}" removido.`);
    await loadClients();
  } catch (e) { toast.err(e.message); }
}

// -- CRUD Admin Users -----------------------------------------------------
let adminUsersCache = [];

async function loadAdminUsers() {
  const tbody = document.getElementById('tbody-admin-users');
  if (!tbody) return;
  try {
    const users = await apiFetch('/admin-users');
    adminUsersCache = users;
    document.getElementById('badge-admin-users').textContent = `${users.filter(u=>u.active).length} ativos / ${users.length} total`;
    if (!users.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="dim" style="padding:14px">Nenhum admin user cadastrado.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map(u => {
      const rolePill = u.role === 'admin'
        ? '<span class="pill pill-client-active">admin</span>'
        : '<span class="pill pill-host">viewer</span>';
      const statusPill = u.active
        ? '<span class="pill pill-client-active">Ativo</span>'
        : '<span class="pill pill-client-inactive">Inativo</span>';
      return `<tr>
        <td><strong>${esc(u.username)}</strong></td>
        <td>${rolePill}</td>
        <td>${statusPill}</td>
        <td><span class="dim">${fmtDate(u.created_at)}</span></td>
        <td><span class="dim">${esc(u.created_by || '—')}</span></td>
        <td><span class="dim">${esc(u.notes || '—')}</span></td>
        <td>
          <button class="btn btn-ghost" style="font-size:.7rem;padding:2px 8px" data-action="openAdminUserModal" data-user-id="${u.id}">Editar</button>
          <button class="btn btn-ghost" style="font-size:.7rem;padding:2px 8px;color:var(--red)" data-action="deleteAdminUser" data-user-id="${u.id}" data-username="${esc(u.username)}">Remover</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7"><div class="inline-msg inline-error fade-in"><span class="inline-msg-icon">${ICONS.error}</span><div><strong>Erro</strong><p>${esc(e.message)}</p></div></div></td></tr>`;
  }
}

let editingAdminUserId = null;

function openAdminUserModal(userIdOrEvent) {
  let userId = userIdOrEvent;
  if (userIdOrEvent && typeof userIdOrEvent === 'object' && userIdOrEvent.currentTarget) {
    const raw = userIdOrEvent.currentTarget.dataset.userId;
    userId = raw ? Number(raw) : null;
  }
  editingAdminUserId = userId || null;
  const isEdit = !!userId;
  document.getElementById('admin-user-modal-title').textContent = isEdit ? 'Editar Admin User' : 'Novo Admin User';
  document.getElementById('admin-user-save-btn').textContent = isEdit ? 'SALVAR' : 'CRIAR';
  document.getElementById('admin-user-active-wrap').style.display = isEdit ? '' : 'none';
  document.getElementById('admin-user-username').disabled = isEdit;

  if (isEdit) {
    const u = adminUsersCache.find(x => x.id === userId) || {};
    document.getElementById('admin-user-username').value = u.username || '';
    document.getElementById('admin-user-password').value = '';
    document.getElementById('admin-user-password').placeholder = 'deixe vazio para manter';
    document.getElementById('admin-user-role').value = u.role || 'viewer';
    document.getElementById('admin-user-notes').value = u.notes || '';
    document.getElementById('admin-user-active').checked = u.active !== false;
    document.getElementById('admin-user-active-label').textContent = u.active !== false ? 'Ativo' : 'Inativo';
  } else {
    document.getElementById('admin-user-username').value = '';
    document.getElementById('admin-user-password').value = '';
    document.getElementById('admin-user-password').placeholder = 'minimo 8 caracteres';
    document.getElementById('admin-user-role').value = 'viewer';
    document.getElementById('admin-user-notes').value = '';
    document.getElementById('admin-user-active').checked = true;
  }
  document.getElementById('admin-user-modal').classList.add('open');
  document.getElementById(isEdit ? 'admin-user-role' : 'admin-user-username').focus();
}

function closeAdminUserModal() {
  document.getElementById('admin-user-modal').classList.remove('open');
  editingAdminUserId = null;
}

document.getElementById('admin-user-active')?.addEventListener('change', function() {
  document.getElementById('admin-user-active-label').textContent = this.checked ? 'Ativo' : 'Inativo';
});

// Event-bus wrapper: <form data-action-submit="saveAdminUserEv">
function saveAdminUserEv(e) {
  if (e && e.preventDefault) e.preventDefault();
  return saveAdminUser();
}

async function saveAdminUser() {
  const username = document.getElementById('admin-user-username').value.trim();
  const password = document.getElementById('admin-user-password').value;
  const role     = document.getElementById('admin-user-role').value;
  const notes    = document.getElementById('admin-user-notes').value.trim();

  if (!editingAdminUserId) {
    if (!username || !password) { toast.warn('Username e senha obrigatorios.'); return; }
    if (password.length < 8) { toast.warn('Senha deve ter no minimo 8 caracteres.'); return; }
    try {
      await apiFetch('/admin-users', {
        method: 'POST',
        body: JSON.stringify({ username, password, role, notes }),
      });
      toast.ok(`Admin user "${username}" criado.`);
      closeAdminUserModal();
      await loadAdminUsers();
    } catch (e) { toast.err(e.message); }
  } else {
    const body = { role, notes };
    if (password) {
      if (password.length < 8) { toast.warn('Senha deve ter no minimo 8 caracteres.'); return; }
      body.password = password;
    }
    body.active = document.getElementById('admin-user-active').checked;
    try {
      await apiFetch(`/admin-users/${editingAdminUserId}`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      });
      toast.ok('Admin user atualizado.');
      closeAdminUserModal();
      await loadAdminUsers();
    } catch (e) { toast.err(e.message); }
  }
}

async function deleteAdminUser(userIdOrEvent, username) {
  let userId = userIdOrEvent;
  if (userIdOrEvent && typeof userIdOrEvent === 'object' && userIdOrEvent.currentTarget) {
    const ds = userIdOrEvent.currentTarget.dataset;
    userId = Number(ds.userId);
    username = ds.username;
  }
  if (!confirm(`Remover admin user "${username}"?`)) return;
  try {
    await apiFetch(`/admin-users/${userId}`, { method: 'DELETE' });
    toast.ok(`Admin user "${username}" removido.`);
    await loadAdminUsers();
  } catch (e) { toast.err(e.message); }
}

document.getElementById('admin-user-modal')?.addEventListener('click', e => {
  if (e.target === e.currentTarget) closeAdminUserModal();
});
