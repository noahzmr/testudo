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
// can reports whether the user may read or write some objects of a kind; a
// permission limited to a site or node ("firewall:write@site:…") counts,
// and the server decides object by object.
const can = (form, verb) => (S.who?.permissions || []).some(p => {
  const [area, rest = ''] = p.split(':');
  const v = rest.split('@')[0];
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
  nat_rule: 'nat', interface: 'ifaces', bond: 'ifaces', bridge: 'ifaces', vlan: 'ifaces', pppoe: 'ifaces',
  route: 'routes', gateway: 'routes', policy_route: 'routes', bgp_neighbor: 'routes', ospf_area: 'routes', vrf: 'routes',
  wg_tunnel: 'wireguard', wg_peer: 'wireguard',
  access_resource: 'access', access_policy: 'access', access_grant: 'access',
  user: 'settings', group: 'settings', role: 'settings', node_settings: 'settings', certificate: 'settings', oidc_provider: 'settings', api_token: 'settings',
  lb_service: 'lb', lb_router: 'lb', lb_backend_pool: 'lb', middleware: 'lb',
  site: 'cluster', cluster_node: 'cluster', fabric: 'cluster', path_policy: 'routes', ha_pair: 'cluster',
  dhcp_scope: 'services', router_advert: 'services', dns_resolver: 'services', dns_record: 'services', ntp_service: 'services', dhcp_relay: 'services',
};
const LABEL = {
  filter_rule: 'Rules', zone: 'Zones', alias: 'Aliases', firewall_policy: 'Policy', nat_rule: 'NAT rules',
  interface: 'Configuration', bond: 'Bonds', bridge: 'Bridges', vlan: 'VLANs', pppoe: 'PPPoE', route: 'Static routes', gateway: 'Gateways', bgp_neighbor: 'BGP', ospf_area: 'OSPF', vrf: 'VRFs', policy_route: 'Policy routes',
  wg_tunnel: 'Tunnels', wg_peer: 'Peers', access_resource: 'Resources', access_policy: 'Policies', access_grant: 'Grants',
  user: 'Users', group: 'Groups', role: 'Roles', node_settings: 'Node settings', certificate: 'Certificates', oidc_provider: 'Identity provider', api_token: 'API tokens',
  lb_service: 'Services', lb_router: 'Routers', lb_backend_pool: 'Pools', middleware: 'Middlewares',
  site: 'Sites', cluster_node: 'Nodes', fabric: 'Fabric', path_policy: 'Path policies', ha_pair: 'HA pairs',
  dhcp_scope: 'DHCP', router_advert: 'Router advertisements', dns_resolver: 'DNS resolver', dns_record: 'DNS records', ntp_service: 'NTP', dhcp_relay: 'DHCP relay',
};
// Friendlier names for some select values.
const OPTION = { acme: "Let's Encrypt", internal_ca: 'Local authority', import: 'Imported',
  'http-01': 'HTTP-01 (port 80)', 'tls-alpn-01': 'TLS-ALPN-01 (port 443)', 'dns-01': 'DNS-01 (wildcards)',
  proxy: 'Proxy (HTTP, TLS, SNI)', kernel: 'Packet filter (TCP/UDP, fastest)' };
// What the running system is driven by today. Everything else is stored,
// versioned and audited, and takes effect when its subsystem moves over.
const ENFORCED = new Set(['filter_rule', 'zone', 'alias', 'firewall_policy', 'nat_rule', 'interface',
  'route', 'gateway', 'policy_route', 'bgp_neighbor', 'ospf_area', 'vrf',
  'wg_tunnel', 'wg_peer', 'access_resource', 'access_policy', 'access_grant',
  'lb_service', 'lb_router', 'lb_backend_pool', 'middleware', 'certificate',
  'user', 'group', 'role', 'oidc_provider', 'api_token', 'fabric', 'path_policy', 'site', 'cluster_node', 'ha_pair',
  'dhcp_scope', 'router_advert', 'dns_resolver', 'dns_record', 'ntp_service']);
// Sections that open on the model instead of their live view.
const OPENS_ON = { firewall: 'filter-rules', nat: 'nat-rules', lb: 'lb-services', cluster: 'cluster-overview', changes: 'changesets', services: 'services-overview' };
const paneOf = seg => seg === 'services-overview' || seg === 'dhcp-leases' ? 'services' : seg === 'cluster-overview' || seg === 'site-flows' ? 'cluster' : seg === 'changesets' || seg === 'history' || seg === 'audit' ? 'changes' : PANE[S.forms.find(f => f.plural === seg)?.kind];
const paneEl = name => document.querySelector(`.pane[data-pane="${name}"]`);

// buildBars gives every section its row of tabs.
function buildBars() {
  const byPane = {};
  for (const [kind, pane] of Object.entries(PANE)) {
    const f = S.byKind[kind];
    if (f && can(f, 'read')) (byPane[pane] ||= []).push(f);
  }
  byPane.changes = [{ plural: 'changesets', label: 'Change sets' }, { plural: 'history', label: 'History' }, { plural: 'audit', label: 'Audit log' }];
  (byPane.services ||= []).unshift({ plural: 'services-overview', label: 'Overview' }, { plural: 'dhcp-leases', label: 'Leases' });
  (byPane.cluster ||= []).unshift({ plural: 'cluster-overview', label: 'Overview' }, { plural: 'site-flows', label: 'Flows across sites' });
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
  if (seg === 'cluster-overview') { S.form = null; return clusterView(); }
  if (seg === 'site-flows') { S.form = null; return siteFlowsView(); }
  if (seg === 'services-overview') { S.form = null; return servicesView(); }
  if (seg === 'dhcp-leases') { S.form = null; return leasesView(); }
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
  } else if (field.type === 'integer' || field.type === 'number') {
    input = el('input', { type: 'number', step: field.type === 'number' ? 'any' : null, disabled: ro, value: value ?? '' });
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
  if (form.kind === 'user' && obj.source === 'local' && !origins) {
    const host = el('section', { class: 'cfg-card' });
    extra.append(host);
    credentialsCard(host, obj, writable);
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

// clusterView is the cluster as this member sees it: who is in it, who
// leads, what each member runs, and whether changes can be made at all.
async function clusterView() {
  const g = gen;
  const [r, rt] = await Promise.all([api('GET', '/cluster'), api('GET', '/runtime')]);
  if (g !== gen) return;
  const main = $('#cfg-main'), c = r.data || {}, fab = rt.data?.fabric;
  const head = el('header', {}, el('h2', { text: 'Cluster' }));
  if (!r.ok) return fill(main, head, el('p', { class: 'err', text: r.data?.message || 'failed' }));
  const act = async (method, path, body, done) => {
    const x = await api(method, path, body);
    if (!x.ok) return toast(x.data?.message || 'failed', 'err');
    done ? done(x.data) : clusterView();
  };
  const admin = (S.who?.permissions || []).some(p => p === '*:write' || p === 'cluster:write');
  if (!c.enabled) {
    return fill(main, head, el('p', { text: 'This node runs alone. To make it part of a cluster, start it with --cluster-raft and --cluster-api (addresses on the site mesh, never on a WAN interface).' }),
      fabricSection(fab, rt.data?.routing?.bgp), haSection(rt.data?.ha));
  }
  if (!c.member) {
    const token = el('textarea', { rows: 3, placeholder: 'tdj1.…', spellcheck: 'false' });
    return fill(main, head,
      el('p', { text: 'This node is ready for a cluster and belongs to none.' }),
      admin ? el('section', { class: 'cfg-card' }, el('h3', { text: 'Start a new cluster here' }),
        el('p', { class: 'dim', text: 'This node becomes the first member. Its configuration becomes the cluster\'s.' }),
        el('button', { type: 'button', class: 'primary', text: 'Start a cluster', onclick: () => { if (confirm('Make this node the first member of a new cluster?')) act('POST', '/cluster/init'); } })) : null,
      admin ? el('section', { class: 'cfg-card' }, el('h3', { text: 'Join an existing cluster' }),
        el('p', { class: 'dim', text: 'Paste a join token from a member of that cluster. This node has to be empty; it receives the cluster\'s configuration.' }),
        token, el('div', { class: 'actions' }, el('button', { type: 'button', text: 'Join', onclick: () => act('POST', '/cluster/join', { token: token.value }) }))) : null);
  }
  const st = c.stats || {};
  const voters = (c.members || []).filter(m => m.role !== 'non-voter').length;
  const warn = [];
  if (!c.quorum) warn.push('This member cannot reach a majority. It keeps running its last configuration and accepts no changes.');
  if (st.halted) warn.push('This member stopped following the cluster: ' + st.halted);
  if (c.quorum && voters === 2) warn.push('Two voters cannot survive the loss of either: one alone is not a majority. Add a third voter at another location; a small witness is enough.');
  if (c.quorum && voters % 2 === 0 && voters > 2) warn.push(`${voters} voters tolerate no more failures than ${voters - 1} would. Use three or five.`);
  const ov = c.override;
  const tokenOut = el('div');
  const mkToken = voter => act('POST', '/cluster/token', { voter, ttl_minutes: 30 }, d => fill(tokenOut,
    el('p', { text: `Join token for a ${voter ? 'voter' : 'member without a vote'}, good once and for 30 minutes:` }), el('pre', { class: 'cfg-secret', text: d.token })));
  const stateText = m => ({ applied: 'applied', pending: 'not there yet', failed: 'failed', drift: 'differs', unknown: 'no report' }[m.state] || m.state)
    + (m.result ? ` · record ${m.result.index}` : '') + (m.result?.error ? ` · ${m.result.error}` : '') + (m.result?.drift ? ` · ${m.result.drift}` : '');
  fill(main, head,
    warn.map(w => el('p', { class: 'err', text: w })),
    ov ? el('section', { class: 'cfg-card' }, el('h3', { text: 'Local override in force on this member' }),
      el('p', { text: `${ov.actor} changed what runs here on ${new Date(ov.at).toLocaleString()}: "${ov.reason}". The configuration was not changed, and this member does not follow the cluster until the override is resolved.` }),
      el('pre', { text: JSON.stringify(ov.ops, null, 1) }),
      admin ? el('button', { type: 'button', text: 'Resolve: go back to the cluster\'s configuration', onclick: () => {
        if (confirm('End the override? Its changes are shown above; make them again as a normal change if they should stay.')) act('DELETE', '/cluster/override');
      } }) : null) : null,
    el('p', { class: 'dim', text: `This member: ${c.id} · leader: ${c.leader || 'none'} · term ${st.term ?? '-'} · committed ${st.commit_index ?? '-'} · applied ${st.applied_index ?? '-'} · configuration record ${c.model_index}` +
      (c.pending ? ` · change ${c.pending.index} by ${c.pending.actor} waits for confirmation` : '') +
      (c.rollout && c.rollout.phase === 'canary' ? ` · rollout: only ${c.rollout.canary} so far` : '') +
      (c.cert_expiry ? ` · certificate until ${new Date(c.cert_expiry).toLocaleDateString()}` : '') }),
    el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Member', 'Role', 'Configuration', 'Build', 'Address', ''].map(h => el('th', { text: h })))),
      el('tbody', {}, (c.members || []).map(m => el('tr', {},
        el('td', { text: m.name || m.id }), el('td', { text: m.in_group ? m.role : 'left' }),
        el('td', { class: m.state === 'failed' || m.state === 'drift' ? 'err' : '', text: stateText(m) }),
        el('td', { class: 'dim', text: m.build || '' }), el('td', { class: 'dim', text: m.raft || '' }),
        el('td', {}, admin && c.quorum && m.id !== c.leader ? [
          m.role === 'non-voter' ? el('button', { type: 'button', text: 'Make voter', onclick: () => act('POST', `/cluster/members/${encodeURIComponent(m.id)}/promote`) })
            : el('button', { type: 'button', text: 'Take vote', onclick: () => act('POST', `/cluster/members/${encodeURIComponent(m.id)}/demote`) }),
          el('button', { type: 'button', text: 'Remove', onclick: () => { if (confirm(`Remove ${m.id} from the cluster? Its certificate is revoked.`)) act('DELETE', `/cluster/members/${encodeURIComponent(m.id)}`); } }),
        ] : null))))),
    admin && c.quorum ? el('div', { class: 'actions' },
      el('button', { type: 'button', text: 'Token for a voter', onclick: () => mkToken(true) }),
      el('button', { type: 'button', text: 'Token for a member without a vote', onclick: () => mkToken(false) }),
      el('button', { type: 'button', text: 'Hand over leadership', onclick: () => act('POST', '/cluster/transfer') })) : null,
    tokenOut,
    el('p', { class: 'dim', text: 'Voters decide: keep three or five, at three locations or more. Members without a vote receive the configuration and do not affect the majority.' }),
    fabricSection(fab, rt.data?.routing?.bgp), haSection(rt.data?.ha));
}

// siteFlowsView lists connections seen at more than one member: where each
// saw it, on which interface and tunnel, over which fabric path. Every
// member's flows are fetched when the view is opened; nothing of it is
// replicated.
async function siteFlowsView() {
  const g = gen;
  const r = await api('GET', '/flows/sites');
  if (g !== gen) return;
  const main = $('#cfg-main'), head = el('header', {}, el('h2', { text: 'Flows across sites' }),
    el('button', { type: 'button', text: 'Refresh', onclick: () => siteFlowsView() }));
  if (!r.ok) return fill(main, head, el('p', { class: 'err', text: r.data?.message || 'failed' }));
  const nodes = r.data.nodes || [], conns = r.data.connections || [];
  const fmt = n => n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' kB' : n + ' B';
  const where = s => [s.attrs?.zone, s.attrs?.tunnel === 'fabric' ? `fabric → ${s.attrs.peer || '?'} via ${s.attrs.path || '?'}${s.attrs.carrier ? ' (encrypted)' : ''}` : s.attrs?.tunnel,
    s.attrs?.pre_nat && s.attrs?.post_nat ? 'NAT ⇒ ' + s.attrs.post_nat.replace(/^\S+ /, '') : ''].filter(Boolean).join(' · ');
  fill(main, head,
    el('p', { class: 'dim', text: 'Members asked: ' + nodes.map(n => `${n.node}${n.site ? ' (' + n.site + ')' : ''}: ${n.error ? 'no answer, ' + n.error : n.flows + ' flows'}`).join(' · ') }),
    conns.length ? el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Connection', 'Sites', 'Path', 'Bytes', 'Seen at'].map(h => el('th', { text: h })))),
      el('tbody', {}, conns.slice(0, 200).map(c => el('tr', {},
        el('td', { text: `${c.proto} ${c.a} → ${c.b}` }), el('td', { text: (c.sites || []).join(', ') }),
        el('td', { text: (c.paths || []).join(', ') }), el('td', { text: fmt(c.bytes || 0) }),
        el('td', {}, (c.sightings || []).map(s => el('div', { class: 'dim', text: `${s.node} ${s.iface || '(socket)'}${where(s) ? ' · ' + where(s) : ''}` }))))))) :
      el('p', { class: 'dim', text: 'No connection was seen at more than one member in the last minutes. Flow capture has to run on the members (Flows tab).' }));
}

// credentialsCard shows whether a local user has a password and a second
// factor, and lets an administrator set them. Nothing secret comes back
// except a new second factor's otpauth URI, shown once.
async function credentialsCard(host, obj, writable) {
  const r = await api('GET', `/users/${obj.id}/credentials`);
  const c = r.ok ? r.data : {};
  const out = el('div');
  const act = async (method, path, body, after) => {
    const x = await api(method, path, body);
    if (!x.ok) return toast(x.data?.message || 'failed', 'err');
    toast('Done');
    if (after) after(x.data); else credentialsCard(host, obj, writable);
  };
  fill(host, el('h3', { text: 'Credentials' }),
    el('p', { class: c.password ? '' : 'err', text: c.password ? 'Has a password.' : 'No password yet: this user cannot log in.' }),
    el('p', { text: c.mfa ? 'Second factor (TOTP) enrolled.' : 'No second factor.' }),
    writable ? el('div', { class: 'actions' },
      el('button', { type: 'button', text: 'Set password', onclick: () => {
        const pw = prompt(`New password for ${obj.username} (at least 10 characters)`);
        if (!pw) return;
        if (prompt('Again') !== pw) return toast('The passwords differ', 'err');
        act('POST', `/users/${obj.id}/password`, { password: pw });
      } }),
      el('button', { type: 'button', text: c.mfa ? 'Replace second factor' : 'Enroll second factor', onclick: () =>
        act('POST', `/users/${obj.id}/totp`, null, d => fill(out, el('p', { text: 'Add this to the authenticator app; it is shown once:' }),
          el('pre', { class: 'cfg-secret', text: d.otpauth }))) }),
      c.mfa ? el('button', { type: 'button', class: 'danger', text: 'Remove second factor', onclick: () => {
        if (confirm(`Remove ${obj.username}'s second factor?`)) act('DELETE', `/users/${obj.id}/totp`);
      } }) : null) : null,
    out);
}

// servicesView shows which network services run on this node, on which
// interfaces, and how full the DHCP scopes are.
async function servicesView() {
  const g = gen;
  const rt = await api('GET', '/runtime');
  if (g !== gen) return;
  const main = $('#cfg-main'), sv = rt.data?.services;
  const head = el('header', {}, el('h2', { text: 'Network services' }), el('button', { type: 'button', text: 'Refresh', onclick: () => servicesView() }));
  if (!rt.ok) return fill(main, head, el('p', { class: 'err', text: rt.data?.message || 'failed' }));
  if (!sv) return fill(main, head, el('p', { class: 'dim', text: 'This node offers no DHCP, DNS or NTP yet. Add a DHCP scope, a DNS resolver or an NTP service in the tabs above; each one names the interfaces it serves, and the firewall opens its port on those interfaces only.' }));
  const NAMES = { 'kea-dhcp4': 'DHCPv4 (Kea)', 'kea-dhcp6': 'DHCPv6 (Kea)', unbound: 'DNS (Unbound)', chronyd: 'NTP (chrony)', radvd: 'Router advertisements (radvd)' };
  const o = sv.open || {};
  const on = { 'kea-dhcp4': o.dhcp4, 'kea-dhcp6': o.dhcp6, unbound: o.dns, chronyd: o.ntp, radvd: o.ra };
  fill(main, head,
    el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Service', 'State', 'Interfaces'].map(h => el('th', { text: h })))),
      el('tbody', {}, Object.entries(sv.daemons || {}).map(([d, st]) => el('tr', {},
        el('td', { text: NAMES[d] || d }), el('td', { class: st === 'running' ? '' : 'err', text: st }),
        el('td', { text: (on[d] || []).join(', ') || (d === 'chronyd' ? 'this node only' : '') }))))),
    o.ha ? el('p', { class: 'dim', text: `DHCP runs hot-standby with the HA partner ${o.ha.peer} over ${o.ha.interface}.` }) : null,
    sv.leases_error ? el('p', { class: 'err', text: 'Leases: ' + sv.leases_error }) : null,
    (sv.scopes || []).length ? el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['DHCP scope', 'Interface', 'Subnet', 'Active leases'].map(h => el('th', { text: h })))),
      el('tbody', {}, sv.scopes.map(s => el('tr', {}, el('td', { text: s.name }), el('td', { text: s.interface }),
        el('td', { text: s.subnet }), el('td', { text: String(s.leases) }))))) : null);
}

// leasesView lists the addresses this node's DHCP servers handed out.
async function leasesView() {
  const g = gen;
  const r = await api('GET', '/dhcp/leases');
  if (g !== gen) return;
  const main = $('#cfg-main');
  const head = el('header', {}, el('h2', { text: 'DHCP leases' }), el('button', { type: 'button', text: 'Refresh', onclick: () => leasesView() }));
  if (!r.ok) return fill(main, head, el('p', { class: 'err', text: r.data?.message || 'failed' }));
  const leases = r.data || [];
  const filter = el('input', { type: 'search', placeholder: 'Filter by address, name or hardware address' });
  const body = el('tbody');
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    fill(body, leases.filter(l => !q || [l.address, l.hostname, l.hw_address, l.duid].some(v => (v || '').toLowerCase().includes(q))).slice(0, 1000)
      .map(l => el('tr', { class: l.active ? '' : 'dim' },
        el('td', { text: l.address }), el('td', { text: l.hostname || '' }), el('td', { text: l.hw_address || l.duid || '' }),
        el('td', { text: `${l.scope || '?'} (${l.interface || '?'})` }),
        el('td', { text: l.active ? 'until ' + new Date(l.expires).toLocaleString() : (l.state === 1 ? 'declined' : 'expired') }))));
  };
  filter.oninput = draw;
  fill(main, head, filter,
    leases.length ? el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Address', 'Name', 'Client', 'Scope', 'Lease'].map(h => el('th', { text: h })))), body) :
      el('p', { class: 'dim', text: 'No leases yet.' }));
  draw();
}

// haSection shows this node's HA pair: whether it holds the virtual
// addresses and whether keepalived and conntrackd run.
function haSection(ha) {
  if (!ha) return null;
  const head = el('h3', { text: 'HA pair on this node' });
  if (ha.error) return el('section', { class: 'cfg-card' }, head, el('p', { class: 'err', text: ha.error }));
  const d = ha.daemons || {};
  const ok = d.keepalived === 'running' && d.conntrackd === 'running';
  return el('section', { class: 'cfg-card' }, head,
    el('p', { class: ok ? '' : 'err', text: `${ha.pair}: ${ha.role === 'active' ? 'active, holds the virtual addresses' : 'standby'} · keepalived ${d.keepalived} · conntrackd ${d.conntrackd} · state sync with ${ha.peer}` }),
    el('p', { class: 'dim', text: `Virtual addresses: ${(ha.virtual_ips || []).join(', ')}` }));
}

// fabricSection shows this member's tunnels to the other sites with what
// was measured on them and whether BGP runs over them.
function fabricSection(fab, bgp) {
  if (!fab) return null;
  const head = el('h3', { text: 'Fabric on this member' });
  if (!fab.enabled) return el('section', { class: 'cfg-card' }, head,
    el('p', { class: fab.error ? 'err' : 'dim', text: fab.error || 'This member is not part of the fabric yet: it needs a node object with a fabric index and uplinks; its key is filled in by itself.' }));
  const paths = Object.fromEntries((fab.paths || []).map(p => [p.device, p]));
  const ms = v => v == null ? '' : `${v.toFixed(1)} ms`;
  return el('section', { class: 'cfg-card' }, head,
    el('p', { class: 'dim', text: `Loopback ${fab.loopback} · AS ${fab.asn} · key ${String(fab.public_key || '').slice(0, 12)}…` }),
    (fab.tunnels || []).length ? el('table', { class: 'cfg-table' },
      el('thead', {}, el('tr', {}, ['Tunnel', 'To', 'Color', 'VRF', 'Session', 'Latency', 'Jitter', 'Loss', ''].map(h => el('th', { text: h })))),
      el('tbody', {}, fab.tunnels.map(t => {
        const p = paths[t.device], s = bgp?.[t.peer];
        const state = !s ? 'not running' : s.state === 'Established' ? `${t.session} up · ${s.received} prefixes` : `${t.session} ${s.state}`;
        return el('tr', {},
          el('td', { text: t.device }), el('td', { text: `${t.peer_node} (${t.endpoint})` }), el('td', { text: t.color }), el('td', { text: t.vrf || '' }),
          el('td', { class: s && s.state === 'Established' ? '' : 'err', text: state }),
          el('td', { text: p ? ms(p.latency_ms) : '' }), el('td', { text: p ? ms(p.jitter_ms) : '' }),
          el('td', { class: p && p.loss > 0.05 ? 'err' : '', text: p ? `${Math.round(p.loss * 100)} %` : '' }),
          el('td', { class: p?.down ? 'err' : 'dim', text: p?.down ? 'down' : p?.preferred ? 'preferred' : '' }));
      }))) : el('p', { class: 'dim', text: 'No tunnels: no other site shares an uplink color with this member.' }));
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
