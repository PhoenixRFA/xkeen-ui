const $ = s => document.querySelector(s);

async function api(path, opts = {}) {
  const r = await fetch(path, {
    credentials: 'same-origin', ...opts,
    headers: { 'X-Requested-With': 'xkeen-ui', 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  let d = null;
  try { d = await r.json(); } catch (e) {}
  if (!r.ok) { const e = new Error((d && d.error) || r.statusText); e.status = r.status; throw e; }
  return d;
}

function show(authed) {
  $('#login').hidden = authed;
  $('#app').hidden = !authed;
}

async function login() {
  $('#err').textContent = '';
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ user: $('#user').value, password: $('#pw').value }) });
    $('#pw').value = '';
    show(true);
  } catch (e) { $('#err').textContent = e.message; }
}

$('#go').onclick = login;
$('#pw').onkeydown = e => { if (e.key === 'Enter') login(); };
$('#out').onclick = async () => { try { await api('/api/logout', { method: 'POST' }); } catch (e) {} show(false); };

(async () => {
  try { $('#ver').textContent = (await api('/api/version')).version; } catch (e) {}
  try { await api('/api/me'); show(true); } catch (e) { show(false); }
})();
