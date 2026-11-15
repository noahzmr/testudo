// Configuration pane of the main console. Every form, table and picker here is built from
// /api/v1/schema/ui.json; nothing is written per entity.
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (k === 'value') n.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'multiple') n[k] = !!v;
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) n.append(kid);
  return n;
}

// fill replaces a node's children, skipping absent ones (replaceChildren
// would render null as the text "null").
function fill(node, ...kids) {
  node?.replaceChildren(...kids.flat().filter(k => k != null));
}

const S = { forms: [], byKind: {}, who: null, form: null, draft: '', editing: null, mask: '********' };

let writing = 0;
const held = [];
function flushHeld() {
  if (writing) return;
  for (const e of held.splice(0)) onChange(e);
}

async function api(method, path, body, headers = {}) {
  const init = { method, headers: { ...headers }, credentials: 'same-origin' };
  if (body !== undefined) { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  // An event for a write can arrive before the write's own response. Events
  // are held while a write is in flight so the echo can be recognised.
  const write = method !== 'GET';
  if (write) writing++;
  let res, text;
  try {
    res = await fetch('/api/v1' + path, init);
    text = await res.text();
  } finally {
    if (write) { writing--; setTimeout(flushHeld, 0); }
  }
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = { message: text }; } }
  return { status: res.status, ok: res.ok, headers: res.headers, data };
}
const can = (form, verb) => (S.who?.permissions || []).some(p => {
  const [area, v] = p.split(':');
  return (area === '*' || area === form.menu.split('/')[0]) && (v === verb || v === 'write');
});

function toast(msg, kind = '') {
  const t = el('div', { class: 'cfg-toast ' + kind, text: msg });
  $('#cfg-toasts').append(t);
  setTimeout(() => t.remove(), 6000);
}

// ---- navigation ----------------------------------------------------------

// Every kind lives in the console section it belongs to. PANE says which;
// LABEL is the name of its tab there. A section that also has a live view
// keeps it as its "Running state" tab.
const PANE = {
  filter_rule: 'firewall', zone: 'firewall', alias: 'firewall', firewall_policy: 'firewall',
  nat_rule: 'nat', interface: 'ifaces',
  route: 'routes', gateway: 'routes', policy_route: 'routes', bgp_neighbor: 'routes', ospf_area: 'routes', vrf: 'routes',
  wg_tunnel: 'wireguard', wg_peer: 'wireguard',
  access_resource: 'access', access_policy: 'access',
  user: 'settings', group: 'settings', role: 'settings', certificate: 'settings', oidc_provider: 'settings', api_token: 'settings',
  lb_service: 'lb', lb_router: 'lb', lb_backend_pool: 'lb', middleware: 'lb',
  site: 'cluster', cluster_node: 'cluster',
};
const LABEL = {
  filter_rule: 'Rules', zone: 'Zones', alias: 'Aliases', firewall_policy: 'Policy', nat_rule: 'NAT rules',
  interface: 'Zone assignment', route: 'Static routes', gateway: 'Gateways', bgp_neighbor: 'BGP', ospf_area: 'OSPF', vrf: 'VRFs', policy_route: 'Policy routes',
  wg_tunnel: 'Tunnels', wg_peer: 'Peers', access_resource: 'Resources', access_policy: 'Policies',
  user: 'Users', group: 'Groups', role: 'Roles', certificate: 'Certificates', oidc_provider: 'Identity provider', api_token: 'API tokens',
  lb_service: 'Services', lb_router: 'Routers', lb_backend_pool: 'Pools', middleware: 'Middlewares',
  site: 'Sites', cluster_node: 'Nodes',
};
// Friendlier names for some select values.
const OPTION = { acme: "Let's Encrypt", internal_ca: 'Local authority', import: 'Imported',
  'http-01': 'HTTP-01 (port 80)', 'tls-alpn-01': 'TLS-ALPN-01 (port 443)', 'dns-01': 'DNS-01 (wildcards)',
  proxy: 'Proxy (HTTP, TLS, SNI)', kernel: 'Packet filter (TCP/UDP, fastest)' };
// What the running system is driven by today. Everything else is stored,
// versioned and audited, and takes effect when its subsystem moves over.
const ENFORCED = new Set(['filter_rule', 'zone', 'alias', 'firewall_policy', 'nat_rule', 'interface',
  'route', 'gateway', 'policy_route', 'bgp_neighbor', 'ospf_area', 'vrf',
  'wg_tunnel', 'wg_peer', 'access_resource', 'access_policy',
  'lb_service', 'lb_router', 'lb_backend_pool', 'middleware', 'certificate',
  'user', 'group', 'role', 'oidc_provider', 'api_token']);
// Sections that open on the model instead of their live view.
const OPENS_ON = { firewall: 'filter-rules', nat: 'nat-rules', lb: 'lb-services', cluster: 'sites', changes: 'changesets' };
const paneOf = seg => seg === 'changesets' || seg === 'history' || seg === 'audit' ? 'changes' : PANE[S.forms.find(f => f.plural === seg)?.kind];
const paneEl = name => document.querySelector(`.pane[data-pane="${name}"]`);

// buildBars gives every section its row of tabs.
function buildBars() {
  const byPane = {};
  for (const [kind, pane] of Object.entries(PANE)) {
    const f = S.byKind[kind];
    if (f && can(f, 'read')) (byPane[pane] ||= []).push(f);
  }
  byPane.changes = [{ plural: 'changesets', label: 'Change sets' }, { plural: 'history', label: 'History' }, { plural: 'audit', label: 'Audit log' }];
  for (const [pane, forms] of Object.entries(byPane)) {
    const host = paneEl(pane);
    if (!host || host.querySelector('.cfg-bar')) continue;
    const live = host.children.length > 0;  // the section has a live view of its own
    const bar = el('div', { class: 'cfg-bar', role: 'tablist' },
      forms.map(f => el('button', { type: 'button', 'data-seg': f.plural, text: f.label || LABEL[f.kind] || f.title,
        onclick: () => { location.hash = '#/' + f.plural; } })),
      live ? el('button', { type: 'button', 'data-seg': '', text: 'Running state', onclick: () => showLive(pane) }) : null);
    host.prepend(bar);
    markBar(pane, live && !OPENS_ON[pane] ? '' : null);
  }
}

function markBar(pane, seg) {
  for (const b of paneEl(pane)?.querySelectorAll('.cfg-bar button') || []) b.classList.toggle('active', b.dataset.seg === seg);
}

// showLive puts a section back on its live view.
function showLive(pane) {
  paneEl(pane)?.classList.remove('cfg-on');
  markBar(pane, '');
  if (location.hash.startsWith('#/')) history.replaceState(null, '', location.pathname + location.search);
}

// mount moves the shared editor into a section and hides its live view.
function mount(pane, seg) {
  const host = paneEl(pane);
  if (!host) return false;
  const shell = $('#cfg-shell');
  if (shell.parentElement !== host) host.querySelector('.cfg-bar').after(shell);
  shell.hidden = false;
  host.classList.add('cfg-on');
  markBar(pane, seg);
  const tab = document.querySelector(`.tab[data-tab="${pane}"]`);
  if (tab && !tab.classList.contains('active')) { switching = true; tab.click(); switching = false; }
  return true;
}
let switching = false;

// Views load data before they render. gen identifies the newest navigation
// so a slower, older view cannot paint over the one the user moved on to.
let gen = 0;
async function route() {
  // The pane shares the page with the rest of the console; only hashes of
  // the form #/<kind>/... belong to it.
  if (!location.hash.startsWith('#/')) return;
  const [, seg, id] = location.hash.split('/');
  const g = ++gen;
  S.editing = null;
  const pane = paneOf(seg);
  if (!pane || !mount(pane, seg)) return;
  if (seg === 'changesets') { S.form = null; return changeSetsView(); }
  if (seg === 'history') { S.form = null; return historyView(); }
  if (seg === 'audit') { S.form = null; return auditView(); }
  S.form = S.forms.find(f => f.plural === seg);
  if (!S.form || !can(S.form, 'read')) return fill($('#cfg-main'), el('p', { text: 'Nothing you may read here.' }));
  if (id === 'new') return S.form.kind === 'api_token' ? tokenView() : editView(S.form, null);
  if (id) {
    const r = await api('GET', `/${S.form.plural}/${id}`);
    if (g !== gen) return;
    if (r.ok) return editView(S.form, r.data);
    toast('Object not found', 'err');
  }
  return listView(S.form);
}

// ---- list ----------------------------------------------------------------

const names = {};  // kind -> { id: name }
async function loadNames(kind) {
  const f = S.byKind[kind];
  if (!f) return {};
  const r = await api('GET', '/' + f.plural);
  names[kind] = Object.fromEntries((r.data || []).map(o => [o.id, o.name]));
  return names[kind];
}

function show(field, v) {
  if (v == null || v === '') return '';
  if (field.type === 'ref') {
    const one = id => names[field.ref]?.[id] || id.slice(0, 8);
    return Array.isArray(v) ? v.map(one).join(', ') : one(v);
  }
  if (field.enum && OPTION[v]) return OPTION[v];
  if (Array.isArray(v)) return field.type === 'object' ? `${v.length} entries` : v.join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

async function listView(form) {
  const main = $('#cfg-main');
  const g = gen;
  const cols = form.fields.filter(f => !f.group?.match(/^(Meta|Scope)$/) && f.name !== 'description').slice(0, 5);
  await Promise.all([...new Set(cols.filter(c => c.type === 'ref').map(c => c.ref))].map(loadNames));
  const [r, rt, hintsRes] = await Promise.all([api('GET', '/' + form.plural), api('GET', '/runtime'),
    form.kind === 'lb_service' ? api('GET', '/lb/firewall-hints') : null]);
  if (g !== gen) return;
  const lb = rt.data?.load_balancer || {}, certs = rt.data?.certificates || {};
  const hints = Object.fromEntries((hintsRes?.data || []).map(h => [h.service, h]));
  // Health of a pool's backends: the proxy reports its own, the kernel
  // path is checked by this program.
  const poolDown = o => (o.backends || []).filter(b => lb.pools?.[o.id]?.backends?.[b.address] === 'DOWN' || lb.backends?.[b.address]?.down);
  // What the running system says about these objects: traffic matched per
  // rule, and how fresh a run-time alias is.
  const counters = rt.data?.counters, feeds = rt.data?.aliases || {};
  const gwHealth = rt.data?.routing?.gateways || {}, sessions = rt.data?.routing?.bgp;
  const live = o => {
    if (form.kind === 'alias') {
      const st = feeds[o.id];
      return !st ? '' : st.error ? `${st.entries} entries · ${st.error}` : `${st.entries} entries · ${new Date(st.refreshed).toLocaleTimeString()}`;
    }
    if (form.kind === 'gateway') {
      const st = gwHealth[o.id];
      return !st ? (o.monitor ? 'not probed yet' : 'not monitored') : st.error ? `unknown · ${st.error}` : `${st.down ? 'down' : 'up'} since ${new Date(st.since).toLocaleTimeString()}`;
    }
    if (form.kind === 'bgp_neighbor') {
      const b = sessions?.[o.address];
      return !sessions ? 'routing daemon not running' : !b ? 'not configured in the daemon' : `${b.state || 'unknown'} · ${b.received ?? 0} prefixes`;
    }
    if (form.kind === 'lb_backend_pool') {
      const st = lb.pools?.[o.id], down = poolDown(o), n = (o.backends || []).length;
      const health = down.length ? `${down.length} of ${n} down (${down.map(b => b.address).join(', ')})` : `${n} backend${n === 1 ? '' : 's'}`;
      return st ? `${health} · ${st.requests.toLocaleString()} requests · ${st.errors.toLocaleString()} errors · ${st.avg_ms.toFixed(1)} ms` : health;
    }
    if (form.kind === 'lb_service') {
      if (!o.enabled) return 'disabled';
      if (o.mode === 'kernel') { const c = counters?.[o.id]; return c ? `packet filter · ${c.packets.toLocaleString()} connections` : 'packet filter'; }
      const h = hints[o.id];
      return `proxy ${lb.process || 'unknown'}${h && !h.covered ? ' · no filter rule lets clients in' : ''}`;
    }
    if (form.kind === 'certificate') {
      const st = certs[o.id];
      if (o.source === 'acme') return o.staging ? "Let's Encrypt staging · renewed automatically" : "Let's Encrypt · renewed automatically";
      return !st ? '' : st.error ? st.error : st.days_left < 0 ? `expired ${new Date(st.not_after).toLocaleDateString()}`
        : `${st.days_left} days left (${new Date(st.not_after).toLocaleDateString()})`;
    }
    const c = counters?.[o.id];
    return c ? `${c.packets.toLocaleString()} pkts` : '';
  };
  const liveTitle = { alias: 'Content', gateway: 'Health', bgp_neighbor: 'Session', lb_backend_pool: 'State', lb_service: 'State', certificate: 'Expiry' }[form.kind] || 'Matched';
  const bad = o => feeds[o.id]?.error || gwHealth[o.id]?.down || (form.kind === 'bgp_neighbor' && sessions && sessions[o.address]?.state !== 'Established')
    || (form.kind === 'lb_backend_pool' && poolDown(o).length) || (form.kind === 'lb_service' && o.enabled && o.mode === 'proxy' && (lb.process !== 'running' || hints[o.id]?.covered === false))
    || (form.kind === 'certificate' && (certs[o.id]?.error || certs[o.id]?.days_left < 14));
  const showLiveCol = (form.kind === 'alias' && Object.keys(feeds).length) || (counters && (form.kind === 'filter_rule' || form.kind === 'nat_rule'))
    || (rt.data?.routing && (form.kind === 'gateway' || form.kind === 'bgp_neighbor'))
    || (rt.data?.load_balancer && (form.kind === 'lb_backend_pool' || form.kind === 'lb_service')) || form.kind === 'certificate';
  // Services no filter rule lets clients reach. The rule is proposed; it
  // is created only when someone asks for it, and then like any other.
  const closed = Object.values(hints).filter(h => !h.covered && h.rule);
  const fr = S.byKind.filter_rule;
  const openUp = closed.length && fr && can(fr, 'write') ? el('div', { class: 'cfg-planned' },
    el('p', { text: `No filter rule lets clients reach: ${closed.map(h => h.name).join(', ')}. With a default-deny policy these services are not reachable.` }),
    closed.map(h => el('button', { type: 'button', text: `Create rule "${h.rule.name}" (${h.rule.protocol} ${h.rule.ports.join(', ')})`, onclick: async () => {
      const res = await api('POST', '/filter-rules', h.rule);
      if (!res.ok) return toast(res.data?.message || 'failed', 'err');
      afterWrite(res); toast('Rule created'); listView(form);
    } }))) : closed.length ? el('p', { class: 'cfg-planned', text: `No filter rule lets clients reach: ${closed.map(h => h.name).join(', ')}.` }) : null;
  const caLink = form.kind === 'certificate' ? el('p', { class: 'dim' }, el('a', { href: '/api/v1/pki/ca', download: 'testudo-ca.pem', text: 'Download the local authority\'s certificate' }),
    el('span', { text: ' for clients that should trust certificates issued here.' })) : null;
  if (!r.ok) return fill(main, el('p', { class: 'err', text: r.data?.message || 'failed' }));
  const rows = (r.data || []).map(o => el('tr', { onclick: () => { location.hash = `#/${form.plural}/${o.id}`; } },
    cols.map(c => el('td', { text: show(c, o[c.name]) })),
    showLiveCol ? el('td', { class: bad(o) ? 'err' : '', text: live(o) }) : null,
    el('td', { text: o.scope }), el('td', { class: 'dim', text: `v${o.version} · ${o.updated_by || ''}` })));
  fill(main, 
    el('header', {},
      el('h2', { text: LABEL[form.kind] || form.title }),
      can(form, 'write') ? el('button', { class: 'primary', text: 'New', onclick: () => { location.hash = `#/${form.plural}/new`; } }) : null),
    ENFORCED.has(form.kind) ? null : el('p', { class: 'cfg-planned', text: 'Stored, versioned and audited. Not applied to the running system yet; use Running state for what is in effect.' }),
    openUp, caLink,
    rows.length ? el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, cols.map(c => el('th', { text: c.label })), showLiveCol ? el('th', { text: liveTitle }) : null, el('th', { text: 'Scope' }), el('th', { text: 'Version' }))),
      el('tbody', {}, rows)) : el('p', { class: 'dim', text: 'No objects yet.' }));
}

// ---- form ----------------------------------------------------------------

// Each widget returns { node, get(), mark(msg) }.
function widget(field, value, ctx) {
  const ro = field.widget === 'readonly' || !ctx.writable;
  let input, get;
  const lines = v => v.split('\n').map(s => s.trim()).filter(Boolean);

  if (field.type === 'object' && field.list) {
    const body = el('tbody');
    const rows = [];
    const add = v => {
      const ws = field.fields.map(sf => widget(sf, v?.[sf.name], ctx));
      const row = { ws, tr: el('tr', {}, ws.map(w => el('td', {}, w.input)),
        el('td', {}, ro ? null : el('button', { type: 'button', text: '×', onclick: () => { rows.splice(rows.indexOf(row), 1); row.tr.remove(); } }))) };
      rows.push(row); body.append(row.tr);
    };
    (value || []).forEach(add);
    input = el('div', {}, el('table', { class: 'cfg-table inner' },
      el('thead', {}, el('tr', {}, field.fields.map(sf => el('th', { text: sf.label })), el('th'))), body),
      ro ? null : el('button', { type: 'button', text: 'Add row', onclick: () => add({}) }));
    get = () => rows.map(r => Object.fromEntries(r.ws.map((w, i) => [field.fields[i].name, w.get()]).filter(([, v]) => v !== undefined)));
  } else if (field.type === 'object') {
    const ws = field.fields.map(sf => [sf, widget(sf, value?.[sf.name], ctx)]);
    input = el('fieldset', { class: 'nested' }, ws.map(([, w]) => w.node));
    get = () => Object.fromEntries(ws.map(([sf, w]) => [sf.name, w.get()]).filter(([, v]) => v !== undefined));
  } else if (field.type === 'ref') {
    input = el('span', { class: 'ref' });
    const sel = el('select', { multiple: field.list, disabled: ro });
    const load = async chosen => {
      const opts = await loadNames(field.ref);
      const want = new Set([].concat(chosen || []));
      fill(sel, field.list ? null : el('option', { value: '', text: '-' }),
        ...Object.entries(opts).sort((a, b) => a[1].localeCompare(b[1])).map(([id, name]) => el('option', { value: id, text: name, selected: want.has(id) })));
    };
    load(value);
    const target = S.byKind[field.ref];
    input.append(sel, !ro && target && can(target, 'write') ? el('button', {
      type: 'button', title: `Create a new ${target.title}`, text: '+ new',
      // Inline creation goes through the same endpoint, validation and audit
      // trail as the target's own menu.
      onclick: () => dialog(target, null, created => load(field.list ? [...get() || [], created.id] : created.id)),
    }) : null);
    get = () => field.list ? [...sel.selectedOptions].map(o => o.value) : (sel.value || undefined);
  } else if (field.widget === 'scope-picker') {
    input = el('select', { disabled: ro });
    (async () => {
      const [sites, nodes] = await Promise.all([loadNames('site'), loadNames('cluster_node')]);
      const opt = (v, t) => el('option', { value: v, text: t, selected: (value || 'global') === v });
      fill(input, opt('global', 'global'),
        ...Object.entries(sites).map(([id, n]) => opt('site:' + id, 'site: ' + n)),
        ...Object.entries(nodes).map(([id, n]) => opt('node:' + id, 'node: ' + n)));
    })();
    get = () => input.value || 'global';
  } else if (field.type === 'boolean') {
    input = el('input', { type: 'checkbox', checked: !!value, disabled: ro });
    get = () => input.checked;
  } else if (field.enum && field.list) {
    const boxes = field.enum.map(v => [v, el('input', { type: 'checkbox', checked: (value || []).includes(v), disabled: ro })]);
    input = el('span', {}, boxes.map(([v, b]) => el('label', { class: 'inline' }, b, ' ' + v)));
    get = () => boxes.filter(([, b]) => b.checked).map(([v]) => v);
  } else if (field.enum) {
    input = el('select', { disabled: ro }, field.required ? null : el('option', { value: '', text: '-' }),
      field.enum.map(v => el('option', { value: v, text: OPTION[v] || v, selected: v === value })));
    get = () => input.value || undefined;
  } else if (field.list) {
    input = el('textarea', { rows: 3, disabled: ro, placeholder: 'one per line', value: (value || []).join('\n') });
    get = () => lines(input.value);
  } else if (field.type === 'map' && field.widget === 'key-value') {
    input = el('textarea', { rows: 3, disabled: ro, placeholder: 'key=value, one per line',
      value: Object.entries(value || {}).map(([k, v]) => `${k}=${v}`).join('\n') });
    get = () => { const o = Object.fromEntries(lines(input.value).map(l => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; })); return Object.keys(o).length ? o : undefined; };
  } else if (field.type === 'map' || field.widget === 'override-list') {
    input = el('textarea', { rows: 3, disabled: ro, placeholder: 'JSON', value: value ? JSON.stringify(value, null, 1) : '' });
    get = () => input.value.trim() ? JSON.parse(input.value) : undefined;
  } else if (field.type === 'integer') {
    input = el('input', { type: 'number', disabled: ro, value: value ?? '' });
    get = () => input.value === '' ? undefined : Number(input.value);
  } else if (field.type === 'datetime') {
    input = el('input', { type: ro ? 'text' : 'datetime-local', disabled: ro, value: value ? String(value).slice(0, 16) : '' });
    get = () => ro ? value : (input.value ? new Date(input.value).toISOString() : undefined);
  } else if (field.widget === 'textarea') {
    input = el('textarea', { rows: 3, disabled: ro, value: value ?? '' });
    get = () => input.value || undefined;
  } else {
    input = el('input', { type: field.secret ? 'password' : 'text', disabled: ro, value: value ?? '', autocomplete: 'off' });
    get = () => input.value || undefined;
  }
  const origin = ctx.origins?.[field.name];
  const msg = el('span', { class: 'err' });
  const node = el('label', { class: 'cfg-field' },
    el('span', { class: 'lbl' }, field.label, field.required ? ' *' : '',
      origin ? el('span', { class: 'badge', title: 'The effective value comes from this scope', text: origin }) : null),
    input, field.help ? el('small', { text: field.help }) : null, msg);
  return { node, input, get, field, mark: m => { msg.textContent = m || ''; node.classList.toggle('bad', !!m); } };
}

function buildForm(form, obj, ctx) {
  const groups = {};
  const ws = [];
  for (const f of form.fields) {
    const w = widget(f, obj?.[f.name], ctx);
    ws.push(w);
    (groups[f.group || ''] ||= []).push(w.node);
  }
  const node = el('div', {}, Object.entries(groups).map(([g, nodes]) =>
    g ? el('details', { class: 'cfg-group', open: g !== 'Meta' ? '' : null }, el('summary', { text: g }), nodes) : el('div', { class: 'cfg-group' }, nodes)));
  const collect = () => {
    const out = {};
    for (const w of ws) {
      if (w.field.widget === 'readonly') { if (obj?.[w.field.name] !== undefined) out[w.field.name] = obj[w.field.name]; continue; }
      const v = w.get();
      if (v !== undefined && !(Array.isArray(v) && !v.length && !w.field.required)) out[w.field.name] = v;
    }
    return out;
  };
  const mark = fields => {
    ws.forEach(w => w.mark(''));
    const rest = [];
    for (const fe of fields || []) {
      const w = ws.find(w => fe.field === w.field.name || fe.field.startsWith(w.field.name + '[') || fe.field.startsWith(w.field.name + '.'));
      if (w) w.mark(`${fe.field}: ${fe.message}`); else rest.push(`${fe.field}: ${fe.message}`);
    }
    return rest;
  };
  return { node, collect, mark, ws };
}

// save sends the form and explains every way the server can refuse it.
async function save(form, obj, body, ui, version) {
  const q = S.draft ? '?changeset=' + S.draft : '';
  const r = obj
    ? await api('PUT', `/${form.plural}/${obj.id}${q}`, body, { 'If-Match': `"${version ?? obj.version}"` })
    : await api('POST', `/${form.plural}${q}`, body);
  fill(ui.status, );
  if (r.ok) { afterWrite(r); return r.status === 202 ? { ...body, id: body.id } : r.data; }
  const p = r.data || {};
  if (p.error === 'invalid') ui.status.append(...ui.form.mark(p.fields).map(m => el('p', { class: 'err', text: m })));
  else if (p.error === 'inconsistent') ui.status.append(...ui.form.mark(p.problems.map(x => ({ field: x.field, message: x.message }))).map(m => el('p', { class: 'err', text: m })));
  else if (p.error === 'conflict') ui.status.append(conflictBox(form, obj, body, p, ui));
  else ui.status.append(el('p', { class: 'err', text: p.message || `failed (${r.status})` }));
  return null;
}

function conflictBox(form, obj, body, p, ui) {
  const fmt = v => v === undefined || v === null ? '(empty)' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  return el('div', { class: 'cfg-conflict' },
    el('strong', { text: `Changed by ${p.current?.updated_by || 'someone else'} while you were editing (now version ${p.current_version}).` }),
    el('table', { class: 'cfg-table' }, el('thead', {}, el('tr', {}, el('th', { text: 'Field' }), el('th', { text: 'Yours' }), el('th', { text: 'Current' }))),
      el('tbody', {}, (p.diff || []).map(d => el('tr', {}, el('td', { text: d.field }), el('td', { text: fmt(d.yours) }), el('td', { text: fmt(d.current) }))))),
    el('button', { type: 'button', text: 'Discard mine, load current', onclick: () => ui.reload(p.current) }),
    el('button', { type: 'button', class: 'danger', text: 'Save mine over it', onclick: async () => { const saved = await save(form, obj, body, ui, p.current_version); if (saved) ui.done(saved); } }));
}

async function editView(form, obj, origins) {
  S.editing = obj ? { kind: form.kind, id: obj.id } : null;
  const writable = can(form, 'write');
  const f = buildForm(form, obj, { writable, origins });
  const status = el('div', { id: 'cfg-status' });
  const ui = { form: f, status, reload: cur => editView(form, cur), done: () => { location.hash = '#/' + form.plural; } };
  const extra = el('div', { class: 'cfg-extra' });
  // Values a helper sets that the form has no editable field for.
  const extras = {};
  const helper = !writable || origins ? null : form.kind === 'certificate' ? certHelpers(obj, f, extras)
    : form.kind === 'oidc_provider' ? oidcHelpers(obj, extras) : wgHelpers(form, obj, f, extras, ui);
  fill($('#cfg-main'), 
    el('header', {}, el('h2', { text: obj ? `${form.title}: ${obj.name}` : `New ${form.title}` }),
      el('a', { href: '#/' + form.plural, text: 'Back' })),
    el('form', { class: 'cfg-form', onsubmit: async ev => {
      ev.preventDefault();
      let body;
      try { body = { ...f.collect(), ...extras }; } catch (e) { fill(status, el('p', { class: 'err', text: 'Invalid JSON in a field: ' + e.message })); return; }
      const saved = await save(form, obj, body, ui);
      if (saved) ui.done(saved);
    } }, f.node, helper, status,
      writable ? el('div', { class: 'actions' },
        el('button', { class: 'primary', text: S.draft ? 'Add to change set' : 'Save and apply' }),
        obj ? el('button', { type: 'button', class: 'danger', text: 'Delete', onclick: () => removeObject(form, obj, status) }) : null) : null),
    extra);
  if (!obj) return;
  if (form.kind === 'wg_peer' && !origins) {
    const host = el('div');
    extra.append(host);
    showClientConfig(host, obj.id, null);
  }
  const used = await api('GET', `/${form.plural}/${obj.id}/used-by`);
  extra.append(el('h3', { text: 'Used by' }), (used.data || []).length
    ? el('ul', {}, used.data.map(u => el('li', {}, el('a', { href: `#/${S.byKind[u.kind]?.plural}/${u.id}`, text: `${u.kind} "${u.name}"` }), ` (${u.field})`)))
    : el('p', { class: 'dim', text: 'Nothing references this object.' }));
  if ((obj.overrides || []).length) {
    const pick = el('select', { onchange: async () => {
      const [level, id] = pick.value.split(':');
      const r = await api('GET', `/${form.plural}/${obj.id}/effective?${level}=${id}`);
      if (r.ok) editView(form, { ...r.data.object, version: obj.version }, r.data.origins);
    } }, el('option', { value: '', text: 'base value' }),
      obj.overrides.map(o => el('option', { value: o.scope, text: 'as seen by ' + o.scope })));
    extra.append(el('h3', { text: 'Effective value' }), pick,
      origins ? el('p', { class: 'dim', text: 'Showing the effective value; badges mark overridden fields. Reload before editing.' }) : null);
  }
}

async function removeObject(form, obj, status) {
  if (!confirm(`Delete ${form.title} "${obj.name}"?`)) return;
  const q = S.draft ? '?changeset=' + S.draft : '';
  const r = await api('DELETE', `/${form.plural}/${obj.id}${q}`, undefined, { 'If-Match': `"${obj.version}"` });
  if (r.ok) { afterWrite(r); location.hash = '#/' + form.plural; return; }
  const p = r.data || {};
  fill(status, el('p', { class: 'err', text: p.error === 'in_use' ? 'Still in use by:' : (p.message || 'failed') }));
  if (p.used_by) status.append(el('ul', {}, p.used_by.map(u => el('li', {}, el('a', { href: `#/${S.byKind[u.kind]?.plural}/${u.id}`, text: `${u.kind} "${u.name}"` }), ` (${u.field})`))));
}

// ---- WireGuard helpers ----------------------------------------------------

const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));

// newClientKeypair makes a key pair for a client device in this browser, so
// the private key never leaves it. Browsers without X25519 fall back to the
// server, which returns the pair once and keeps nothing.
async function newClientKeypair() {
  try {
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = await crypto.subtle.exportKey('raw', pair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
    return { private_key: b64(pkcs8.slice(-32)), public_key: b64(pub), where: 'in this browser' };
  } catch {
    const r = await api('POST', '/wg/client-keypair');
    if (!r.ok) throw new Error(r.data?.message || 'key generation failed');
    return { ...r.data, where: 'on the appliance (this browser cannot)' };
  }
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[src="${src}"]`)) return resolve();
    document.head.append(el('script', { src, onload: resolve, onerror: reject }));
  });
}

// showClientConfig presents a peer's configuration. With secrets it is the
// complete file, shown this once; without, it has placeholders.
async function showClientConfig(host, peerID, secrets) {
  const r = await api('GET', `/wg-peers/${peerID}/client-config`);
  if (!r.ok) return fill(host, el('p', { class: 'err', text: r.data?.message || 'No client configuration.' }));
  let text = r.data.config;
  const complete = !!secrets?.private_key;
  if (secrets?.private_key) text = text.replace(r.data.private_key_placeholder, secrets.private_key);
  if (secrets?.preshared_key) text = text.replace(r.data.preshared_key_placeholder, secrets.preshared_key);
  const qr = el('div', { class: 'cfg-qr' });
  fill(host, el('h3', { text: 'Client configuration' }),
    el('p', { class: complete ? 'err' : 'dim', text: complete
      ? 'This is the only time the complete configuration is shown. The private key exists nowhere else.'
      : 'The private key stays on the device that generated it, and a preshared key is shown only when it is created.' }),
    el('pre', { text }),
    complete ? el('div', { class: 'actions' },
      el('a', { class: 'btn', download: 'wireguard.conf', href: 'data:text/plain;charset=utf-8,' + encodeURIComponent(text), text: 'Download' })) : null,
    complete ? qr : null);
  if (complete) {
    try {
      await loadScript('/static/vendor/qrcode.js');
      window.qrcode.stringToBytes = window.qrcode.stringToBytesFuncs['UTF-8'];
      const q = window.qrcode(0, 'M');
      q.addData(text, 'Byte'); q.make();
      qr.innerHTML = q.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
      qr.querySelector('svg')?.setAttribute('width', '260');
    } catch { fill(qr, el('span', { class: 'dim', text: 'QR code unavailable; use the text or the download.' })); }
  }
}

// certHelpers adds the two ways to get a certificate whose key lives on the
// node: issue one from the internal authority, or import one with its key.
// Either way the private key goes to the node's secret store and the form
// only receives the name of its entry.
function certHelpers(obj, f, extras) {
  const input = name => f.ws.find(w => w.field.name === name)?.input;
  const note = el('span', { class: 'dim' });
  const key = el('textarea', { rows: 6, placeholder: '-----BEGIN PRIVATE KEY-----', spellcheck: 'false', autocomplete: 'off' });
  const took = (data, text) => {
    extras.key_ref = data.key_ref;
    extras.not_after = data.not_after;
    if (input('source')) input('source').value = data.source;
    if (input('chain_pem')) input('chain_pem').value = data.chain_pem;
    note.textContent = text;
  };
  return el('div', { class: 'cfg-extra' },
    el('div', { class: 'actions' },
      el('button', { type: 'button', text: obj ? 'Issue again from the local authority' : 'Issue from the local authority', onclick: async () => {
        let domains;
        try { domains = f.collect().domains; } catch { domains = null; }
        if (!domains?.length) return toast('Enter the domains first', 'err');
        const r = await api('POST', '/pki/issue', { domains });
        if (!r.ok) return toast(r.data?.message || 'failed', 'err');
        took(r.data, `Issued, valid until ${new Date(r.data.not_after).toLocaleDateString()}. Save to use it.`);
      } }), note),
    el('details', {}, el('summary', { text: 'Import a certificate with its private key' }),
      el('p', { class: 'dim', text: 'Paste the certificate chain into the field above and the private key here. The key is checked against the certificate, stored on the node, and not shown again.' }),
      key,
      el('div', { class: 'actions' }, el('button', { type: 'button', text: 'Check and store the key', onclick: async () => {
        const chain = input('chain_pem')?.value;
        if (!chain || !key.value) return toast('Both the chain and the key are needed', 'err');
        const r = await api('POST', '/pki/import', { chain_pem: chain, key_pem: key.value });
        if (!r.ok) return toast(r.data?.message || 'failed', 'err');
        key.value = '';
        took(r.data, `Key stored; the certificate is valid until ${new Date(r.data.not_after).toLocaleDateString()}. Save to use it.`);
      } }))));
}

// wgHelpers adds the buttons that create key material for tunnels and peers.
function wgHelpers(form, obj, f, extras, ui) {
  const input = name => f.ws.find(w => w.field.name === name)?.input;
  const note = el('span', { class: 'dim' });
  if (form.kind === 'wg_tunnel') {
    return el('div', { class: 'actions' }, el('button', { type: 'button', text: obj ? 'Rotate the tunnel key' : 'Create the tunnel key on this node', onclick: async () => {
      const r = await api('POST', '/wg/tunnel-key');
      if (!r.ok) return toast(r.data?.message || 'failed', 'err');
      input('public_key').value = r.data.public_key;
      extras.key_ref = r.data.key_ref;
      note.textContent = obj ? 'New key created. Saving puts it into effect; every client then needs the new public key.'
        : 'Key created on the node. The private key never leaves it; save to use it.';
    } }), note);
  }
  if (form.kind !== 'wg_peer') return null;
  const secrets = {};
  const done = ui.done;
  // After saving with fresh secrets, stay and show the complete file once.
  ui.done = saved => {
    if (!secrets.private_key || !saved?.id || S.draft) return done(saved);
    const host = el('div', { class: 'cfg-extra' });
    fill($('#cfg-main'), el('header', {}, el('h2', { text: `Peer ${saved.name} is ready` }), el('a', { href: '#/' + form.plural, text: 'Done' })), host);
    showClientConfig(host, saved.id, secrets);
  };
  return el('div', { class: 'actions' },
    el('button', { type: 'button', text: obj ? 'Rotate the key pair' : 'Generate a key pair', onclick: async () => {
      try {
        const pair = await newClientKeypair();
        secrets.private_key = pair.private_key;
        input('public_key').value = pair.public_key;
        note.textContent = `Key pair generated ${pair.where}. Save to see the client configuration.`;
      } catch (e) { toast(e.message, 'err'); }
    } }),
    el('button', { type: 'button', text: 'Add a preshared key', onclick: async () => {
      const r = await api('POST', '/wg/preshared-key');
      if (!r.ok) return toast(r.data?.message || 'failed', 'err');
      extras.preshared_ref = r.data.preshared_ref;
      secrets.preshared_key = r.data.preshared_key;
      note.textContent = 'Preshared key created. It is part of the client configuration shown after saving.';
    } }), note);
}

// dialog edits or creates an object on top of the current view.
function dialog(form, obj, onSaved) {
  const f = buildForm(form, obj, { writable: true });
  const status = el('div');
  const dlg = el('dialog', { class: 'cfg-dialog' });
  const ui = { form: f, status, reload: () => {}, done: saved => { dlg.close(); dlg.remove(); onSaved(saved); } };
  dlg.append(el('h3', { text: `New ${form.title}` }), el('form', { class: 'cfg-form', onsubmit: async ev => {
    ev.preventDefault();
    let body;
    try { body = f.collect(); } catch (e) { fill(status, el('p', { class: 'err', text: e.message })); return; }
    // A stable id lets the caller reference the object even while it only
    // exists in a change set.
    body.id ||= crypto.randomUUID();
    const saved = await save(form, obj, body, ui);
    if (saved) ui.done(saved);
  } }, f.node, status, el('div', { class: 'actions' },
    el('button', { class: 'primary', text: 'Create' }),
    el('button', { type: 'button', text: 'Cancel', onclick: () => { dlg.close(); dlg.remove(); } }))));
  document.body.append(dlg);
  dlg.showModal();
}

// ---- pending confirmation ------------------------------------------------

let confirmTimer = null;
const own = new Set();  // record indexes written from this page
function afterWrite(r) {
  if (r.status === 202) { toast('Added to the change set'); refreshDrafts(); return; }
  if (r.headers.get('Testudo-Pending')) {
    own.add(Number(r.headers.get('Testudo-Pending')));
    showPending(r.headers.get('Testudo-Confirm-By'));
  }
}
// The change is live. That this page still reaches the server is the proof
// that management access survived, so it confirms after a short pause in
// which the operator can still take the change back.
function showPending(deadline) {
  const bar = $('#cfg-pending');
  clearTimeout(confirmTimer);
  let left = 5;
  const tick = async () => {
    if (left-- > 0) {
      fill(bar, `Applied. Confirming in ${left + 1}s (rolls back by itself at ${new Date(deadline).toLocaleTimeString()} otherwise) `,
        el('button', { text: 'Roll back now', onclick: async () => { clearTimeout(confirmTimer); await api('POST', '/apply/rollback', { reason: 'rolled back from the configuration page' }); bar.hidden = true; toast('Rolled back'); route(); } }));
      bar.hidden = false;
      confirmTimer = setTimeout(tick, 1000);
      return;
    }
    const r = await api('POST', '/apply/confirm');
    bar.hidden = true;
    toast(r.ok ? 'Change confirmed' : 'Could not confirm: ' + (r.data?.message || r.status), r.ok ? '' : 'err');
  };
  tick();
}

// ---- change sets and history ---------------------------------------------

async function refreshDrafts() {
  const r = await api('GET', '/changesets');
  const sel = $('#cfg-draft');
  const mine = (r.data || []);
  fill(sel, el('option', { value: '', text: 'Apply immediately' }),
    ...mine.map(c => el('option', { value: c.id, text: `Change set: ${c.name} (${c.ops}, ${c.owner})`, selected: c.id === S.draft })));
  if (!mine.some(c => c.id === S.draft)) S.draft = '';
  return mine;
}

function changeRows(changes) {
  const changed = c => {
    if (c.type !== 'update') return '';
    const keys = new Set([...Object.keys(c.before || {}), ...Object.keys(c.after || {})]);
    return [...keys].filter(k => !/^(version|updated_at|updated_by)$/.test(k) && JSON.stringify(c.before?.[k]) !== JSON.stringify(c.after?.[k])).join(', ');
  };
  return el('table', { class: 'cfg-table' }, el('tbody', {}, (changes || []).map(c =>
    el('tr', {}, el('td', { class: 'op-' + c.type, text: c.type }), el('td', { text: c.kind }), el('td', { text: c.name }), el('td', { class: 'dim', text: changed(c) })))));
}

async function changeSetsView() {
  const main = $('#cfg-main');
  const g = gen;
  const sets = await refreshDrafts();
  const out = el('div');
  const boxes = [];
  const chosen = () => boxes.filter(([, b]) => b.checked).map(([id]) => id);
  const run = async (path, note) => {
    if (!chosen().length) return toast('Select at least one change set', 'err');
    const r = await api('POST', path, { changesets: chosen(), note });
    if (!r.ok) return fill(out, el('p', { class: 'err', text: r.data?.message || 'failed' }));
    if (path === '/plan') {
      fill(out, el('h3', { text: 'Combined diff' }), changeRows(r.data.changes),
        ...Object.entries(r.data.rendered || {}).map(([stage, text]) => el('details', {}, el('summary', { text: 'Rendered: ' + stage }), el('pre', { text }))));
    } else { afterWrite(r); changeSetsView(); }
  };
  const cards = await Promise.all(sets.map(async c => {
    const v = (await api('GET', '/changesets/' + c.id)).data;
    const box = el('input', { type: 'checkbox' });
    boxes.push([c.id, box]);
    return el('section', { class: 'cfg-card' },
      el('header', {}, el('label', { class: 'inline' }, box, ' ', el('strong', { text: c.name })), el('span', { class: 'dim', text: ` by ${c.owner}` }),
        el('button', { text: 'Discard', onclick: async () => { if (confirm('Discard this change set?')) { await api('DELETE', '/changesets/' + c.id); changeSetsView(); } } })),
      v.problem ? el('p', { class: 'err', text: 'No longer applies: ' + v.problem }) : changeRows(v.changes));
  }));
  if (g !== gen) return;
  const name = el('input', { placeholder: 'Name of a new change set' });
  const note = el('input', { placeholder: 'Note for the history (optional)' });
  fill(main, el('header', {}, el('h2', { text: 'Change sets' })),
    el('p', { class: 'dim', text: 'Prepare changes without applying them, review the combined diff, then apply several change sets as one transaction.' }),
    el('div', { class: 'actions' }, name, el('button', { text: 'Create', onclick: async () => {
      const r = await api('POST', '/changesets', { name: name.value });
      if (!r.ok) return toast(r.data?.message || 'failed', 'err');
      S.draft = r.data.id; changeSetsView();
    } })),
    ...cards,
    sets.length ? el('div', { class: 'actions' }, note,
      el('button', { text: 'Review combined diff', onclick: () => run('/plan') }),
      el('button', { class: 'primary', text: 'Apply selected', onclick: () => run('/apply', note.value) })) : null,
    out);
}

async function historyView() {
  const g = gen;
  const r = await api('GET', '/history?limit=50');
  if (g !== gen) return;
  fill($('#cfg-main'), el('header', {}, el('h2', { text: 'History' })),
    ...(r.data || []).map(rec => el('section', { class: 'cfg-card' },
      el('header', {}, el('strong', { text: `#${rec.index} ${rec.type}` }),
        el('span', { class: 'dim', text: ` ${new Date(rec.time).toLocaleString()} · ${rec.actor}${rec.note ? ' · ' + rec.note : ''}` }),
        (rec.changes || []).length ? el('button', { text: 'Revert', onclick: async () => {
          if (!confirm(`Revert record ${rec.index}?`)) return;
          const x = await api('POST', `/history/${rec.index}/revert`);
          if (x.ok) { afterWrite(x); historyView(); } else toast(x.data?.message || 'failed', 'err');
        } }) : null),
      changeRows(rec.changes))));
}

// auditView lists who did what: logins with their source, configuration
// changes with what they changed, applies, rollbacks, privileged operations.
async function auditView() {
  const g = gen;
  const r = await api('GET', '/audit?limit=300');
  if (g !== gen) return;
  const main = $('#cfg-main');
  if (!r.ok) return fill(main, el('header', {}, el('h2', { text: 'Audit log' })), el('p', { class: 'err', text: r.data?.message || 'failed' }));
  const detail = row => {
    let d;
    try { d = JSON.parse(row.detail); } catch { return row.detail; }
    if (d === null || typeof d !== 'object') return row.detail;
    return Object.entries(d).filter(([, v]) => v !== '' && v != null)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join(' · ');
  };
  fill(main, el('header', {}, el('h2', { text: 'Audit log' })),
    el('p', { class: 'dim', text: 'Newest first. The values before and after a configuration change are in History, under the record number.' }),
    el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Time', 'Who', 'What', 'Detail', 'Result'].map(h => el('th', { text: h })))),
      el('tbody', {}, (r.data || []).map(row => el('tr', {},
        el('td', { text: new Date(row.time).toLocaleString() }), el('td', { text: row.actor || '-' }), el('td', { text: row.op }),
        el('td', { text: detail(row) }), el('td', { class: row.result === 'ok' ? '' : 'err', text: row.result }))))));
}

// tokenView creates an API token. A token carries some of its creator's
// own permissions and is shown once.
function tokenView() {
  const main = $('#cfg-main');
  const name = el('input', { placeholder: 'ci-deploy', required: true });
  const ttl = el('input', { type: 'number', min: 0, max: 8784, value: 720 });
  const perms = (S.who?.permissions || []).flatMap(p => p.endsWith(':write') ? [p.replace(':write', ':read'), p] : [p]);
  const boxes = [...new Set(perms)].sort().map(p => el('label', { class: 'check' }, el('input', { type: 'checkbox', value: p }), el('span', { text: ' ' + p })));
  const status = el('div');
  fill(main, el('header', {}, el('h2', { text: 'New API token' }), el('a', { href: '#/api-tokens', text: 'Back' })),
    el('form', { class: 'cfg-form', onsubmit: async ev => {
      ev.preventDefault();
      const chosen = boxes.map(b => b.querySelector('input')).filter(i => i.checked).map(i => i.value);
      if (!chosen.length) return fill(status, el('p', { class: 'err', text: 'Choose at least one permission.' }));
      const r = await api('POST', '/tokens', { name: name.value, permissions: chosen, ttl_hours: Number(ttl.value) || 0 });
      if (!r.ok) return fill(status, el('p', { class: 'err', text: r.data?.message || 'failed' }));
      fill(main, el('header', {}, el('h2', { text: `Token ${r.data.name}` }), el('a', { href: '#/api-tokens', text: 'Done' })),
        el('p', { text: 'Copy the token now. It is not stored and cannot be shown again.' }),
        el('pre', { class: 'cfg-secret', text: r.data.token }),
        el('p', { class: 'dim', text: 'Send it as "Authorization: Bearer <token>". ' + (r.data.expires_at ? `It expires ${new Date(r.data.expires_at).toLocaleString()}.` : 'It does not expire; disable it when it is no longer needed.') }));
    } },
      el('label', {}, el('span', { text: 'Name *' }), name),
      el('label', {}, el('span', { text: 'Valid for (hours, 0 = no expiry)' }), ttl),
      el('fieldset', {}, el('legend', { text: 'Permissions (yours, or fewer)' }), boxes),
      status, el('div', { class: 'actions' }, el('button', { class: 'primary', text: 'Create token' }))));
}

// oidcHelpers stores the provider's client secret on the node. The form
// only receives the name of the entry.
function oidcHelpers(obj, extras) {
  const secret = el('input', { type: 'password', autocomplete: 'off', placeholder: obj ? 'leave empty to keep the stored secret' : 'client secret' });
  const note = el('span', { class: 'dim' });
  return el('div', { class: 'cfg-extra' },
    el('label', {}, el('span', { text: 'Client secret' }), secret),
    el('div', { class: 'actions' }, el('button', { type: 'button', text: 'Store the secret on this node', onclick: async () => {
      if (!secret.value) return toast('Enter the secret first', 'err');
      const r = await api('POST', '/oidc/client-secret', { secret: secret.value });
      if (!r.ok) return toast(r.data?.message || 'failed', 'err');
      secret.value = '';
      extras.client_secret_ref = r.data.client_secret_ref;
      note.textContent = 'Stored. Save to use it.';
    } }), note),
    el('p', { class: 'dim', text: 'Register this console at the provider with the redirect URL above and, for logout by the provider, the back-channel logout URL <console address>/auth/oidc/backchannel-logout. Local and host accounts keep working when the provider is unreachable.' }));
}

// ---- live updates ---------------------------------------------------------

function onChange(e) {
  // Skip the echo of this page's own writes, but not changes the same
  // user makes in another tab or session.
  if (own.delete(e.index) && !e.resync) return;
  for (const c of e.changes || []) {
    toast(`${c.kind} "${c.name}" ${c.type}d by ${e.actor}`);
    if (S.editing && S.editing.kind === c.kind && S.editing.id === c.id) {
      fill($('#cfg-status'), el('p', { class: 'err', text: `This object was just changed by ${e.actor}. Saving will show the differences.` }));
    }
  }
  if (!S.editing && !document.querySelector('dialog[open]')) route();
}

function listen() {
  const es = new EventSource('/api/v1/events');
  es.addEventListener('change', ev => {
    const e = JSON.parse(ev.data);
    if (writing) held.push(e); else onChange(e);
  });
  es.addEventListener('apply', ev => {
    const e = JSON.parse(ev.data);
    if (e.event === 'rolled_back') { toast(`Change #${e.index} was rolled back: ${e.reason}`, 'err'); $('#cfg-pending').hidden = true; if (!S.editing) route(); }
    if (e.event === 'rollback_failed') toast(`Rollback of #${e.index} is incomplete: ${e.error}`, 'err');
  });
}

async function main() {
  const [ui, who] = await Promise.all([api('GET', '/schema/ui.json'), api('GET', '/whoami')]);
  if (!ui.ok) { fill($('#cfg-main'), el('p', { class: 'err', text: ui.data?.message || 'The configuration model is unavailable.' })); return; }
  S.forms = ui.data.forms; S.mask = ui.data.secret_mask; S.who = who.data;
  for (const f of S.forms) S.byKind[f.kind] = f;
  $('#cfg-draft').addEventListener('change', ev => { S.draft = ev.target.value; route(); });
  await refreshDrafts();
  const st = await api('GET', '/apply');
  if (st.data?.pending) showPending(st.data.pending.deadline);
  window.addEventListener('hashchange', route);
  listen();
  buildBars();
  // A section that opens on the model does so when it is selected; the
  // others open on their live view. A deep link (#/aliases/...) switches
  // the console to the right section.
  for (const tab of document.querySelectorAll('.tab[data-tab]')) {
    tab.addEventListener('click', () => {
      if (switching) return;
      const pane = tab.dataset.tab, seg = OPENS_ON[pane];
      if (!seg) return showLive(pane);
      if (location.hash.split('/')[1] && paneOf(location.hash.split('/')[1]) === pane) return route();
      if (location.hash === '#/' + seg) route(); else location.hash = '#/' + seg;
    });
  }
  if (location.hash.startsWith('#/')) route();
}
main();
