window.FS = (() => {
  async function api(path, opts = {}) {
    const res = await fetch(`/api/v1${path}`, {
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json', ...(opts.headers || {}) },
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (res.status === 401 && !opts.allow401) { location.href = '/login?next=' + encodeURIComponent(location.pathname); throw new Error('unauthorized'); }
    if (!res.ok) { const e = new Error((data && data.message) || 'Request failed'); e.status = res.status; e.data = data; throw e; }
    return data;
  }
  const money = (cents, cur = 'USD') => new Intl.NumberFormat('en-US', { style: 'currency', currency: cur }).format((cents || 0) / 100);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const $ = (sel, root = document) => root.querySelector(sel);
  function alertBox(el, msg, kind = 'error') { el.className = `alert ${kind} show`; el.textContent = msg; }
  const logo = `<svg viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#1f7a4d"/><path d="M16 6c-4 4-6 8-6 12a6 6 0 0 0 12 0c0-4-2-8-6-12Z" fill="#bfe8d0"/><path d="M16 11v15" stroke="#1f7a4d" stroke-width="1.8" stroke-linecap="round"/><path d="M16 17l-3-2.5M16 21l3-2.5" stroke="#1f7a4d" stroke-width="1.6" stroke-linecap="round"/></svg>`;
  async function shell(active) {
    const me = await api('/me');
    const nav = [['/app', 'Expenses', 'expenses'], ['/app/settings', 'Settings', 'settings'], ['/developers', 'Developers', 'dev']];
    document.getElementById('side').innerHTML = `
      <a class="logo" href="/app">${logo}<span>Fernspend</span></a>
      ${nav.map(([h, l, k]) => `<a class="item ${k === active ? 'active' : ''}" href="${h}">${l}</a>`).join('')}
      <div class="spacer"></div>
      <div class="ws"><div style="font-weight:600">${esc(me.organization.name)}</div>
        <div class="muted small">${esc(me.user.email)} · ${esc(me.role)}</div>
        <button class="btn btn-sm w100" style="margin-top:10px" id="logout">Sign out</button></div>`;
    $('#logout').onclick = async () => { await api('/auth/logout', { method: 'POST' }); location.href = '/login'; };
    return me;
  }
  return { api, money, esc, $, alertBox, logo, shell };
})();
