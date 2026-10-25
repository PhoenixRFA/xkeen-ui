const $ = s => document.querySelector(s);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };

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

let busy = false;
function show(authed) { $('#login').hidden = authed; $('#app').hidden = !authed; if (authed) loadAll(); }
function lockUI(v) { busy = v; document.querySelectorAll('#app button').forEach(b => b.disabled = v); }

async function login() {
  $('#err').textContent = '';
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ user: $('#user').value, password: $('#pw').value }) });
    $('#pw').value = ''; show(true);
  } catch (e) { $('#err').textContent = e.message; }
}
$('#go').onclick = login;
$('#pw').onkeydown = e => { if (e.key === 'Enter') login(); };
$('#out').onclick = async () => { try { await api('/api/logout', { method: 'POST' }); } catch (e) {} show(false); };

function fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : '—'; }

function renderStatus(d) {
  $('#dot').className = 'dot ' + (d.running ? 'on' : 'off');
  $('#st').textContent = (d.running ? 'Running (pid ' + d.pid + ')' : 'Stopped') + (d.status_text ? ' — ' + d.status_text : '');
  $('#ver2').textContent = d.xray_version || '';
  const s = d.subscription;
  $('#sub').textContent = 'Last check: ' + (s.last_check || '—') + (s.last_message ? ' (' + s.last_message + ')' : '') +
    '\nContent changed: ' + fmtDate(s.changed_at) + '\nEntries: ' + s.entries;
  $('#sub').style.whiteSpace = 'pre-line';
  renderMain(d.main);
}

function renderMain(m) {
  if (!m) return;
  $('#eff').textContent = m.effective || 'none (check MAIN_REMARK)';
  if (document.activeElement !== $('#main')) $('#main').value = m.remark || '';
  const parts = $('#parts'); parts.replaceChildren();
  (m.parts || []).forEach((p, i) => {
    const row = el('div', (p.ok ? '✓ ' : '✗ ') + (i === 0 ? '' : 'fallback: ') + p.text + (p.ok ? ' → ' + p.remark : ' (' + p.matches + ' matches, skipped)'), p.ok ? 'ok' : 'warn');
    parts.append(row);
  });
  const ul = $('#nodes'); ul.replaceChildren();
  (m.remarks || []).forEach(r => ul.append(el('li', r)));
}

async function loadStatus() { try { renderStatus(await api('/api/xkeen/status')); } catch (e) { if (e.status === 401) show(false); } }

async function loadAll() {
  loadStatus();
  try { const f = await api('/api/files'); const sel = $('#file'); sel.replaceChildren(); f.files.forEach(n => sel.append(el('option', n))); } catch (e) {}
}

async function runJob(title, start) {
  if (busy) return;
  lockUI(true);
  $('#jobcard').hidden = false; $('#jobname').textContent = title; $('#jobout').textContent = 'Running…';
  try {
    const r = await start();
    let out = (r.warnings || []).map(w => 'warning: ' + w).join('\n');
    for (;;) {
      await new Promise(res => setTimeout(res, 1000));
      const j = await api('/api/jobs/' + r.job);
      if (j.state === 'running') continue;
      $('#jobname').textContent = title + ' — ' + (j.state === 'done' ? 'done' : 'failed');
      $('#jobout').textContent = [out, j.output, j.error && 'error: ' + j.error].filter(Boolean).join('\n');
      break;
    }
  } catch (e) {
    if (e.status === 401) { show(false); return; }
    $('#jobname').textContent = title + ' — failed'; $('#jobout').textContent = e.message;
  }
  lockUI(false);
  loadStatus();
}

const post = p => () => api(p, { method: 'POST' });
document.querySelectorAll('[data-act]').forEach(b => b.onclick = () => {
  const a = b.dataset.act;
  if ((a === 'stop' || a === 'restart') && !confirm(a + ' XKeen? Proxying will be interrupted.')) return;
  const map = { start: ['Start', '/api/xkeen/start'], stop: ['Stop', '/api/xkeen/stop'], restart: ['Restart', '/api/xkeen/restart'],
                test: ['Test config', '/api/xkeen/test'], sub: ['Update subscription', '/api/subscription/update'] };
  runJob(map[a][0], post(map[a][1]));
});
$('#setmain').onclick = () => {
  if (!confirm('Apply main node? XKeen restarts if the generated config changes.')) return;
  runJob('Set main node', () => api('/api/main-vpn', { method: 'PUT', body: JSON.stringify({ remark: $('#main').value }) }));
};
$('#view').onclick = async () => {
  const out = $('#fileout');
  try {
    const f = await api('/api/files/' + $('#file').value + ($('#reveal').checked ? '?reveal=1' : ''));
    out.textContent = (f.masked ? '// secrets masked\n' : '') + f.content;
  } catch (e) { out.textContent = e.message; }
  out.hidden = false;
};

(async () => {
  try { $('#ver').textContent = (await api('/api/version')).version; } catch (e) {}
  try { await api('/api/me'); show(true); } catch (e) { show(false); }
})();
