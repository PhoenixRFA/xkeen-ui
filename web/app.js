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
  loadClients();
  try { const n = await api('/api/check/nodes'); const sel = $('#node'); sel.replaceChildren(); n.nodes.forEach(t => sel.append(el('option', t))); } catch (e) {}
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

let pol = { policies: [], clients: [] };

function renderClients() {
  const q = $('#q').value.toLowerCase();
  const box = $('#clients'); box.replaceChildren();
  pol.clients.filter(c => !q || (c.name + ' ' + c.ip + ' ' + c.mac).toLowerCase().includes(q)).forEach(c => {
    const row = el('div', null, 'client');
    const left = el('div');
    const title = el('div', c.name, 'cname');
    title.append(el('span', null, 'dot ' + (c.online ? 'on' : '')));
    left.append(title, el('div', (c.ip || '—') + ' · ' + c.mac, 'mut small'));
    const sel = document.createElement('select');
    const opts = [['', 'Default (no policy)']].concat(pol.policies.map(p => [p.id, p.id + ' · ' + p.name]));
    if (c.policy && !pol.policies.some(p => p.id === c.policy)) opts.push([c.policy, c.policy + ' (unknown)']);
    opts.forEach(([v, t]) => { const o = el('option', t); o.value = v; sel.append(o); });
    sel.value = c.policy || '';
    const hl = () => sel.classList.toggle('hl', !!(pol.policies.find(p => p.id === sel.value) || {}).highlight);
    hl();
    sel.onchange = async () => {
      sel.disabled = true;
      try {
        await api('/api/clients/' + encodeURIComponent(c.mac) + '/policy', { method: 'PUT', body: JSON.stringify({ policy: sel.value || null }) });
        c.policy = sel.value; $('#unsaved').hidden = false; hl();
      } catch (e) {
        if (e.status === 401) { show(false); return; }
        alert('Failed: ' + e.message); sel.value = c.policy || '';
      }
      sel.disabled = false;
    };
    row.append(left, sel); box.append(row);
  });
  if (!box.children.length) box.append(el('div', 'No clients', 'mut'));
  $('#ccount').textContent = '(' + pol.clients.length + ')';
}

async function loadClients() {
  try { pol = await api('/api/clients'); $('#unsaved').hidden = !pol.unsaved; renderClients(); }
  catch (e) { if (e.status === 401) show(false); else { $('#clients').replaceChildren(el('div', e.message, 'warn')); } }
}
$('#q').oninput = renderClients;
$('#savecfg').onclick = async e => {
  e.preventDefault(); e.stopPropagation();
  try { await api('/api/system/save', { method: 'POST' }); $('#unsaved').hidden = true; }
  catch (e) { alert(e.message); }
};

// collapse state of the Clients card is remembered
const cc = $('#clientsCard');
try { if (localStorage.getItem('xk.clients') === '1') cc.open = true; } catch (e) {}
cc.addEventListener('toggle', () => { try { localStorage.setItem('xk.clients', cc.open ? '1' : '0'); } catch (e) {} });

// ---- checks ----
function lines(pre, items) { pre.replaceChildren(); items.forEach(([t, c]) => pre.append(el('div', t, c))); pre.hidden = false; }
async function withBusy(btn, pre, fn) {
  const label = btn.textContent; btn.disabled = true; btn.textContent = 'Running…';
  try { lines(pre, await fn()); }
  catch (e) { if (e.status === 401) { show(false); return; } lines(pre, [[e.message, 'warn']]); }
  btn.disabled = false; btn.textContent = label;
}
const echo = (label, e) => e.ok
  ? [[label + ': ' + e.ip + ' · avg ' + e.avg_ms + ' ms (' + e.times_ms.join(', ') + ') via ' + e.service, 'ok']]
  : [[label + ': failed — ' + (e.error || 'no response'), 'warn']];

$('#chkRouter').onclick = e => withBusy(e.target, $('#outRouter'), async () => {
  const d = await api('/api/check/router', { method: 'POST' }), p = d.ping, n = d.dns;
  return [
    [p.ok ? 'Ping ' + p.target + ': ' + p.loss_pct + '% loss, avg ' + p.avg_ms + ' ms' : 'Ping ' + p.target + ': FAILED' + (p.error ? ' — ' + p.error : ''), p.ok ? 'ok' : 'warn'],
    [n.ok ? 'DNS ' + n.probe + ' @' + n.server + ': ' + n.ip + ' (' + n.ms + ' ms)' : 'DNS ' + n.probe + ' @' + n.server + ': FAILED', n.ok ? 'ok' : 'warn'],
    ...echo('Direct IP', d.direct)];
});

$('#chkSite').onclick = e => withBusy(e.target, $('#outSite'), async () => {
  const d = await api('/api/check/site', { method: 'POST', body: JSON.stringify({ domain: $('#domain').value }) });
  const note = ['IP-level check only: domain rules from 05_routing.json are not evaluated.', 'mut'];
  if (d.verdict === 'unresolved') return [[d.domain + ': cannot resolve', 'warn'], [d.dns_output || '', 'mut']];
  const head = [d.domain + ' → ' + d.ip, ''];
  if (d.verdict === 'direct') return [head, ['DIRECT — in ' + d.set + ', bypasses the tunnel', 'ok'], note];
  if (d.verdict === 'tunnel') return [head, ['VIA TUNNEL — not in ' + d.set, 'ok'], note];
  return [head, ['ipset check failed: ' + (d.error || d.ipset_output || 'unknown'), 'warn']];
});

$('#chkTunnel').onclick = e => withBusy(e.target, $('#outTunnel'), async () => {
  const d = await api('/api/check/tunnel', { method: 'POST', body: JSON.stringify({ node: $('#node').value }) });
  if (d.ok) return [['Tunnel OK (' + d.node + ')', 'ok'], ...echo('Exit IP', d.tunnel), ...echo('Direct IP', d.direct),
    [d.via_vpn ? 'Traffic leaves via the VPN node (IPs differ).' : 'Exit IP equals the direct IP — traffic is NOT going through a VPN.', d.via_vpn ? 'ok' : 'warn']];
  const out = [['Tunnel DOWN (' + d.node + '): ' + (d.error || 'no response'), 'warn']];
  if (d.probe) out.push([d.probe.ok ? 'Reachable by IP (' + d.probe.url + '): looks like a DNS problem.' : 'Not reachable by IP either: channel or node problem.', 'mut']);
  if (d.xray_log) out.push([d.xray_log, 'mut']);
  return out;
});

// ---- logs ----
async function loadLog() {
  const o = $('#logout');
  try { o.textContent = (await api('/api/logs/' + $('#logname').value + '?n=' + $('#logn').value)).content || '(empty)'; o.scrollTop = o.scrollHeight; }
  catch (e) { if (e.status === 401) show(false); else o.textContent = e.message; }
}
$('#logrefresh').onclick = loadLog;
$('#logname').onchange = loadLog;
$('#logn').onchange = loadLog;
$('#logsCard').addEventListener('toggle', () => { if ($('#logsCard').open) loadLog(); });

// ---- sub.curl ----
async function loadBackups() {
  const sel = $('#subbk'); sel.replaceChildren(el('option', 'Backups…')); sel.firstChild.value = '';
  try {
    (await api('/api/sub-curl/backups')).backups.forEach(b => {
      const o = el('option', b.name.replace('sub.curl.', '') + ' (' + b.size + ' B)'); o.value = b.name; sel.append(o);
    });
  } catch (e) {}
}
async function loadSubCurl() {
  try {
    const d = await api('/api/sub-curl');
    $('#subcurl').value = d.content;
    $('#submsg').textContent = d.exists ? 'Loaded.' : 'File does not exist yet; saving will create it.';
  } catch (e) { if (e.status === 401) { show(false); return; } $('#submsg').textContent = e.message; }
  loadBackups();
}
async function saveSubCurl(thenUpdate) {
  const msg = $('#submsg'); msg.className = 'mut small';
  try {
    const d = await api('/api/sub-curl', { method: 'PUT', body: JSON.stringify({ content: $('#subcurl').value }) });
    msg.textContent = 'Saved' + (d.backup ? ' (previous version: ' + d.backup.replace('sub.curl.', '') + ')' : '') + '.';
    loadBackups();
    if (thenUpdate) runJob('Update subscription', post('/api/subscription/update'));
  } catch (e) { if (e.status === 401) { show(false); return; } msg.textContent = e.message; msg.className = 'warn small'; }
}
$('#subsave').onclick = () => saveSubCurl(false);
$('#subsaveupd').onclick = () => saveSubCurl(true);
$('#subbkload').onclick = async () => {
  const name = $('#subbk').value; if (!name) return;
  try { $('#subcurl').value = (await api('/api/sub-curl/backups/' + name)).content; $('#submsg').textContent = 'Backup loaded into the editor. Press Save to apply it.'; }
  catch (e) { $('#submsg').textContent = e.message; }
};
$('#subcurlCard').addEventListener('toggle', () => { if ($('#subcurlCard').open) loadSubCurl(); });

(async () => {
  try { $('#ver').textContent = (await api('/api/version')).version; } catch (e) {}
  try { await api('/api/me'); show(true); } catch (e) { show(false); }
})();
