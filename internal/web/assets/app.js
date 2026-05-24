// Testudo web UI — single-page app with full feature parity to the TUI.
// All mutations POST JSON to /api/<feature>/<verb>; the snapshot endpoint
// returns the unified state that drives every read view.
(function () {
  'use strict';

  // ---- Tab switching ----
  const tabs = document.querySelectorAll('.tab');
  const panes = document.querySelectorAll('.pane');
  tabs.forEach(btn => btn.addEventListener('click', () => {
    tabs.forEach(b => b.classList.toggle('active', b === btn));
    const target = btn.dataset.tab;
    panes.forEach(p => p.classList.toggle('active', p.dataset.pane === target));
  }));

  // ---- Toast ----
  const toast = document.getElementById('toast');
  let toastTimer = null;
  function showToast(msg, isErr) {
    toast.textContent = msg;
    toast.classList.toggle('error', !!isErr);
    toast.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
  }

  // ---- API helpers ----
  async function api(path, method, body) {
    const init = { method: method || 'GET' };
    if (body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    if (res.status === 401) {
      window.location.href = '/login';
      return null;
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || (res.status + ' ' + res.statusText));
    }
    if (res.status === 204) return null;
    return res.json();
  }
  async function post(path, body) {
    try {
      const r = await api(path, 'POST', body || {});
      return r;
    } catch (e) {
      showToast(String(e.message || e), true);
      throw e;
    }
  }

  // ---- Action dispatcher (single delegated listener) ----
  document.addEventListener('click', async (ev) => {
    const btn = ev.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    try {
      await handleAction(action, btn);
      refresh();
    } catch (_) { /* showToast already happened */ }
  });

  async function handleAction(action, btn) {
    switch (action) {
      case 'capture-start': {
        const raw = document.getElementById('capture-ifaces-input').value.trim();
        const ifaces = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
        await post('/api/capture/start', { ifaces });
        showToast('capture started');
        break;
      }
      case 'capture-stop':
        await post('/api/capture/stop');
        showToast('capture stopped');
        break;
      case 'capture-clear':
        await post('/api/capture/clear');
        showToast('flow table cleared');
        break;
      case 'iface-up':
        await post('/api/iface/up', { name: btn.dataset.name });
        showToast(btn.dataset.name + ' up');
        break;
      case 'iface-down':
        await post('/api/iface/down', { name: btn.dataset.name });
        showToast(btn.dataset.name + ' down');
        break;
      case 'iface-add-addr': {
        const cidr = prompt('CIDR to add to ' + btn.dataset.name + ' (e.g. 192.168.1.20/24)');
        if (!cidr) return;
        await post('/api/iface/addr/add', { name: btn.dataset.name, cidr: cidr.trim() });
        showToast('address added');
        break;
      }
      case 'iface-del-addr': {
        const cidr = prompt('CIDR to remove from ' + btn.dataset.name);
        if (!cidr) return;
        await post('/api/iface/addr/del', { name: btn.dataset.name, cidr: cidr.trim() });
        showToast('address removed');
        break;
      }
      case 'iface-mtu': {
        const mtu = prompt('MTU for ' + btn.dataset.name, '1500');
        if (!mtu) return;
        await post('/api/iface/mtu', { name: btn.dataset.name, mtu: parseInt(mtu, 10) });
        showToast('MTU set');
        break;
      }
      case 'iface-dhcp':
        if (!confirm('Switch ' + btn.dataset.name + ' to DHCP? Existing addresses will be flushed.')) return;
        await post('/api/iface/dhcp', { name: btn.dataset.name });
        showToast('DHCP requested on ' + btn.dataset.name);
        break;
      case 'iface-static': {
        const cidr = prompt('Static CIDR for ' + btn.dataset.name);
        if (!cidr) return;
        await post('/api/iface/static', { name: btn.dataset.name, cidr: cidr.trim() });
        showToast('static address set');
        break;
      }
      case 'route-add':
        await post('/api/route/add', {
          cidr: val('route-cidr'),
          gateway: val('route-gw'),
          iface: val('route-iface'),
        });
        showToast('route added');
        clearInputs(['route-cidr', 'route-gw', 'route-iface']);
        break;
      case 'route-del':
        if (!confirm('Delete route ' + btn.dataset.cidr + '?')) return;
        await post('/api/route/del', { cidr: btn.dataset.cidr });
        showToast('route deleted');
        break;
      case 'fw-add':
        await post('/api/firewall/add', {
          chain:     val('fw-chain'),
          action:    val('fw-action'),
          proto:     val('fw-proto'),
          port:      parseInt(val('fw-port') || '0', 10),
          in_iface:  val('fw-iif'),
          out_iface: val('fw-oif'),
          src:       val('fw-src'),
          dst:       val('fw-dst'),
        });
        showToast('rule added');
        clearInputs(['fw-port', 'fw-iif', 'fw-oif', 'fw-src', 'fw-dst']);
        break;
      case 'fw-del': {
        const rule = JSON.parse(btn.dataset.rule);
        if (!confirm('Delete rule on chain=' + rule.chain + ' port=' + rule.port + '?')) return;
        await post('/api/firewall/del', rule);
        showToast('rule deleted');
        break;
      }
      case 'nat-add':
        await post('/api/nat/add', {
          proto:    val('nat-proto'),
          wan_port: parseInt(val('nat-wan'), 10),
          lan_ip:   val('nat-lanip'),
          lan_port: parseInt(val('nat-lanport') || '0', 10),
        });
        showToast('port forward added');
        clearInputs(['nat-wan', 'nat-lanip', 'nat-lanport']);
        break;
      case 'nat-del':
        if (!confirm('Delete forward ' + btn.dataset.proto + '/' + btn.dataset.port + '?')) return;
        await post('/api/nat/del', {
          proto: btn.dataset.proto,
          wan_port: parseInt(btn.dataset.port, 10),
        });
        showToast('forward removed');
        break;
      case 'td-start':
        await post('/api/tcpdump/start', {
          iface:        val('td-iface'),
          name:         val('td-name'),
          max_size_mb:  parseInt(val('td-size') || '0', 10),
          duration_sec: parseInt(val('td-dur') || '0', 10),
          proto:        val('td-proto'),
          src_host:     val('td-srch'),
          dst_host:     val('td-dsth'),
          src_port:     val('td-srcp'),
          dst_port:     val('td-dstp'),
          raw_filter:   val('td-raw'),
        });
        showToast('capture started');
        break;
      case 'td-stop':
        await post('/api/tcpdump/stop', { id: btn.dataset.id });
        showToast('capture stopping…');
        break;
      case 'td-remove':
        if (!confirm('Delete capture ' + btn.dataset.id + ' (file will be removed)?')) return;
        await post('/api/tcpdump/remove', { id: btn.dataset.id });
        showToast('capture removed');
        break;
      case 'device-scan': {
        showToast('scanning ' + btn.dataset.ip + '…');
        const r = await post('/api/device/scan', { ip: btn.dataset.ip });
        const protos = (r && r.protocols) || [];
        showToast(protos.length
          ? btn.dataset.ip + ' offers ' + protos.map(p => p.toUpperCase()).join(' · ')
          : btn.dataset.ip + ' — no connection ports open');
        break;
      }
      case 'probe-run': {
        const out = document.getElementById('probe-out');
        out.textContent = 'running…';
        try {
          const r = await api('/api/probe', 'POST', {
            kind: val('probe-kind'),
            target: val('probe-target'),
            port: parseInt(val('probe-port') || '0', 10),
          });
          out.textContent = JSON.stringify(r, null, 2);
        } catch (e) {
          out.textContent = 'error: ' + e.message;
        }
        break;
      }
      case 'settings-save':
        await post('/api/settings', collectSettings());
        showToast('settings saved');
        break;
    }
  }

  function val(id) { return (document.getElementById(id).value || '').trim(); }
  function clearInputs(ids) { ids.forEach(id => { document.getElementById(id).value = ''; }); }

  function collectSettings() {
    return {
      packet_loss_pct:      parseFloat(val('s-loss')) || 0,
      dns_latency_ms:       parseFloat(val('s-dns')) || 0,
      jitter_ms:            parseFloat(val('s-jitter')) || 0,
      rtt_ms:               parseFloat(val('s-rtt')) || 0,
      retransmissions_pct:  parseFloat(val('s-retrans')) || 0,
      incident_cooldown_sec: parseFloat(val('s-cooldown')) || 0,
      allow_netops_write:   document.getElementById('s-allow').checked,
      sentry_dsn:           val('s-sentry'),
      guacamole_url:        val('s-guac-url'),
      guacamole_conn_id:    val('s-guac-cid'),
      guacamole_template:   val('s-guac-tpl'),
      ipfix_enabled:        document.getElementById('s-ipfix-en').checked,
      ipfix_endpoint:       val('s-ipfix-ep'),
      ipfix_interval_sec:   parseInt(val('s-ipfix-int') || '0', 10),
      ipfix_domain_id:      parseInt(val('s-ipfix-dom') || '0', 10),
    };
  }

  // ---- Render helpers ----
  function escape(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function fmtBytes(n) {
    if (!n) return '0';
    const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0; let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
  }
  function fmtUs(us) {
    if (!us) return '—';
    if (us < 1000) return us + 'µs';
    return (us / 1000).toFixed(1) + 'ms';
  }

  // ---- Sparkline (inline SVG) ----
  function spark(values, color) {
    if (!values || values.length === 0) {
      return '<svg class="spark-svg"><line x1="0" y1="13" x2="100%" y2="13" stroke="#30363d"/></svg>';
    }
    const w = 200;
    const h = 26;
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const range = (max - min) || 1;
    const step = values.length > 1 ? w / (values.length - 1) : 0;
    const points = values.map((v, i) =>
      i * step + ',' + (h - ((v - min) / range) * (h - 4) - 2)
    ).join(' ');
    return '<svg class="spark-svg" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">'
      + '<polyline fill="none" stroke="' + (color || '#58a6ff') + '" stroke-width="1.2" points="' + points + '"/></svg>';
  }

  function gradeLetter(score) {
    if (score >= 85) return 'A';
    if (score >= 70) return 'B';
    if (score >= 60) return 'C';
    if (score >= 50) return 'D';
    return 'F';
  }

  // ---- Renderers (one per pane) ----
  function renderGrade(g) {
    const badge = document.getElementById('grade-badge');
    badge.textContent = g.letter || '—';
    badge.className = 'grade-badge ' + gradeLetter(g.score || 0);
    document.getElementById('grade-score').textContent = g.score || 0;
    document.getElementById('grade-verdict').textContent = g.verdict || '—';
    const bars = document.getElementById('grade-bars');
    const rows = [
      ['Loss',   g.loss_score,   g.score],
      ['RTT',    g.rtt_score,    g.score],
      ['Jitter', g.jitter_score, g.score],
      ['DNS',    g.dns_score,    g.score],
    ];
    bars.innerHTML = rows.map(([label, score]) => {
      const color = score >= 85 ? '#3fb950'
                 : score >= 70 ? '#d29922'
                 : score >= 60 ? '#db6d28'
                 :              '#f85149';
      return '<div class="grade-bar">'
        + '<span>' + escape(label) + '</span>'
        + '<div class="grade-bar-track"><div class="grade-bar-fill" style="width:' + (score || 0) + '%;background:' + color + '"></div></div>'
        + '<span class="grade-bar-value">' + (score || 0) + '</span>'
        + '</div>';
    }).join('');
  }

  function renderBandwidth(rows) {
    const el = document.getElementById('bandwidth-list');
    if (!rows || rows.length === 0) {
      el.innerHTML = '<div class="muted">…awaiting first sample</div>';
      return;
    }
    el.innerHTML = rows.map(b => {
      const rxLast = fmtBytes(b.current_rx || 0) + '/s';
      const txLast = fmtBytes(b.current_tx || 0) + '/s';
      const rxPeak = fmtBytes(b.peak_rx || 0) + '/s';
      const txPeak = fmtBytes(b.peak_tx || 0) + '/s';
      return ''
        + '<div class="spark" title="rx ' + rxLast + ' · peak ' + rxPeak + '">'
        +   '<span class="spark-label">' + escape(b.iface) + ' &darr; rx</span>'
        +   spark(b.rx || [], '#3fb950')
        +   '<span class="spark-value">' + rxLast + '</span>'
        + '</div>'
        + '<div class="spark" title="tx ' + txLast + ' · peak ' + txPeak + '">'
        +   '<span class="spark-label">' + escape(b.iface) + ' &uarr; tx</span>'
        +   spark(b.tx || [], '#d29922')
        +   '<span class="spark-value">' + txLast + '</span>'
        + '</div>';
    }).join('');
  }

  function renderTalkers(hosts, procs, services) {
    document.getElementById('talkers-hosts-body').innerHTML = (hosts || []).map((h, i) => {
      const zone = h.is_lan
        ? '<span class="status-pill">LAN</span>'
        : '<span class="status-pill on">WAN</span>';
      const name = (h.dns && h.dns !== h.host) ? h.dns : h.host;
      return '<tr>'
        + '<td>' + (i + 1) + '</td>'
        + '<td>' + escape(name) + (h.dns && h.dns !== h.host ? ' <span class="muted">(' + escape(h.host) + ')</span>' : '') + '</td>'
        + '<td>' + zone + '</td>'
        + '<td>' + fmtBytes(h.bytes) + '</td>'
        + '<td>' + h.packets + '</td>'
        + '<td>' + h.flows + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">no flows yet — start capture</td></tr>';

    document.getElementById('talkers-procs-body').innerHTML = (procs || []).map((p, i) =>
      '<tr>'
      + '<td>' + (i + 1) + '</td>'
      + '<td>' + escape(p.process) + '</td>'
      + '<td>' + fmtBytes(p.bytes) + '</td>'
      + '<td>' + p.packets + '</td>'
      + '<td>' + p.flows + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="5" class="muted">no flows with process info</td></tr>';

    document.getElementById('talkers-services-body').innerHTML = (services || []).map((s, i) =>
      '<tr>'
      + '<td>' + (i + 1) + '</td>'
      + '<td>' + escape(s.service) + '</td>'
      + '<td>' + escape((s.proto || '').toUpperCase()) + '</td>'
      + '<td>' + (s.port || '—') + '</td>'
      + '<td>' + fmtBytes(s.bytes) + '</td>'
      + '<td>' + s.packets + '</td>'
      + '<td>' + s.flows + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="7" class="muted">no services classified yet</td></tr>';
  }

  function renderSparks(containerID, series, color) {
    const el = document.getElementById(containerID);
    const names = Object.keys(series);
    if (names.length === 0) {
      el.innerHTML = '<div class="muted">…awaiting samples</div>';
      return;
    }
    el.innerHTML = names.map(name => {
      const vals = series[name];
      const last = vals.length ? vals[vals.length - 1].toFixed(1) + 'ms' : '—';
      return '<div class="spark"><span class="spark-label">' + escape(name) + '</span>'
        + spark(vals, color)
        + '<span class="spark-value">' + last + '</span></div>';
    }).join('');
  }

  function renderTargets(rows) {
    document.getElementById('targets-body').innerHTML = (rows || []).map(t => {
      const lossClass = t.loss_pct >= 8 ? 'loss-err' : t.loss_pct >= 2 ? 'loss-warn' : 'loss-ok';
      return '<tr>'
        + '<td>' + escape(t.target) + '</td>'
        + '<td>' + fmtUs(t.last_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.avg_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.p95_rtt_us) + '</td>'
        + '<td class="' + lossClass + '">' + t.loss_pct.toFixed(1) + '%</td>'
        + '<td>' + t.jitter_ms.toFixed(1) + 'ms</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">…awaiting first probe</td></tr>';
  }

  function renderDNS(rows) {
    document.getElementById('dns-body').innerHTML = (rows || []).map(d =>
      '<tr>'
      + '<td>' + escape(d.name) + '</td>'
      + '<td>' + fmtUs(d.last_us) + '</td>'
      + '<td>' + fmtUs(d.avg_us) + '</td>'
      + '<td>' + d.queries + '</td>'
      + '<td>' + (d.failures > 0 ? '<span class="loss-warn">' + d.failures + '</span>' : '0') + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="5" class="muted">…awaiting first query</td></tr>';
  }

  function renderFlows(rows) {
    const filter = (val('flow-filter') || '').toLowerCase();
    const lines = (rows || []).filter(f => {
      if (!filter) return true;
      return [f.proto, f.iface, f.process, f.a, f.b, f.dns].some(x =>
        String(x || '').toLowerCase().includes(filter));
    });
    document.getElementById('flows-body').innerHTML = lines.map(f =>
      '<tr>'
      + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
      + '<td>' + escape(f.iface) + '</td>'
      + '<td>' + escape(f.process || '—') + '</td>'
      + '<td>' + escape(f.a) + '</td>'
      + '<td>' + escape(f.b) + '</td>'
      + '<td>' + escape(f.service || '—') + '</td>'
      + '<td>' + escape(f.dns || '—') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="9" class="muted">no flows; start capture in this tab</td></tr>';

    document.getElementById('flows-body-dash').innerHTML = (rows || []).slice(0, 5).map(f =>
      '<tr>'
      + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
      + '<td>' + escape(f.iface) + '</td>'
      + '<td>' + escape(f.process || '—') + '</td>'
      + '<td>' + escape(f.a) + '</td>'
      + '<td>' + escape(f.b) + '</td>'
      + '<td>' + escape(f.service || '—') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="8" class="muted">…awaiting flows</td></tr>';
  }

  function renderDevices(rows) {
    document.getElementById('devices-body').innerHTML = (rows || []).map(d => {
      const ports = (d.open_ports || []).length
        ? (d.open_ports || []).map(p => '<code>' + p + '</code>').join(' ')
        : '<span class="muted">—</span>';
      const connectBtns = (d.protocols || []).map(p =>
        '<a class="btn btn-small connect" target="_blank" rel="noopener"'
        + ' href="/api/connect?host=' + encodeURIComponent(d.ip)
        + '&proto=' + encodeURIComponent(p)
        + '&port=' + encodeURIComponent(portForProto(p, d.open_ports))
        + '">' + escape(p.toUpperCase()) + '</a>'
      ).join(' ') || '<span class="muted">scan first</span>';
      const ip = escape(d.ip);
      return '<tr>'
        + '<td><b>' + ip + '</b></td>'
        + '<td>' + escape(d.hostname || '—') + '</td>'
        + '<td>' + escape(d.vendor || '—') + '</td>'
        + '<td>' + ports + '</td>'
        + '<td>' + connectBtns + '</td>'
        + '<td>'
        +   '<button class="btn btn-small" data-action="device-scan" data-ip="' + ip + '">Scan</button>'
        + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">no devices yet</td></tr>';
  }

  // portForProto returns the canonical port for a given protocol that the
  // device actually has open. Lets one-click Connect skip a port picker.
  function portForProto(proto, openPorts) {
    const order = {
      ssh:    [22],
      telnet: [23],
      rdp:    [3389, 3390],
      vnc:    [5900, 5901, 5800],
      http:   [80, 8080, 8081],
      https:  [443, 8443],
    };
    const candidates = order[proto] || [];
    const open = openPorts || [];
    for (const p of candidates) {
      if (open.includes(p)) return p;
    }
    // Fallback: any port that's open and not strictly mapped — empty so
    // the connect builder uses its protocol default.
    return '';
  }

  function renderIfaces(rows) {
    document.getElementById('ifaces-body').innerHTML = (rows || []).map(i => {
      const state = i.up
        ? '<span class="status-pill on">UP</span>'
        : '<span class="status-pill off">DOWN</span>';
      const n = escape(i.name);
      return '<tr>'
        + '<td><b>' + n + '</b></td>'
        + '<td>' + state + '</td>'
        + '<td>' + i.mtu + '</td>'
        + '<td>' + escape(i.hw) + '</td>'
        + '<td>' + (i.addrs || []).map(escape).join(', ') + '</td>'
        + '<td>' + fmtBytes(i.rx_bytes) + '</td>'
        + '<td>' + fmtBytes(i.tx_bytes) + '</td>'
        + '<td>'
        + '<button class="btn btn-small" data-action="iface-up" data-name="' + n + '">up</button> '
        + '<button class="btn btn-small" data-action="iface-down" data-name="' + n + '">down</button> '
        + '<button class="btn btn-small" data-action="iface-add-addr" data-name="' + n + '">+ip</button> '
        + '<button class="btn btn-small" data-action="iface-del-addr" data-name="' + n + '">-ip</button> '
        + '<button class="btn btn-small" data-action="iface-mtu" data-name="' + n + '">mtu</button> '
        + '<button class="btn btn-small" data-action="iface-dhcp" data-name="' + n + '">DHCP</button> '
        + '<button class="btn btn-small" data-action="iface-static" data-name="' + n + '">static</button>'
        + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="8" class="muted">no interfaces visible</td></tr>';
  }

  function renderRoutes(rows) {
    document.getElementById('routes-body').innerHTML = (rows || []).map(r =>
      '<tr>'
      + '<td>' + escape(r.family) + '</td>'
      + '<td>' + escape(r.dst) + '</td>'
      + '<td>' + escape(r.gateway || '—') + '</td>'
      + '<td>' + escape(r.iface) + '</td>'
      + '<td>' + escape(r.proto) + '</td>'
      + '<td>' + r.metric + '</td>'
      + '<td><button class="btn btn-small btn-danger" data-action="route-del" data-cidr="' + escape(r.dst) + '">del</button></td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="7" class="muted">no routes</td></tr>';
  }

  function renderFirewall(rules, system) {
    document.getElementById('fw-rules-body').innerHTML = (rules || []).map(r => {
      const dataRule = JSON.stringify(r).replace(/"/g, '&quot;');
      return '<tr>'
        + '<td>' + escape(r.chain) + '</td>'
        + '<td>' + escape(r.action.toUpperCase()) + '</td>'
        + '<td>' + escape(r.proto.toUpperCase() || '—') + '</td>'
        + '<td>' + (r.port || '—') + '</td>'
        + '<td>' + escape(r.in_iface || '—') + '</td>'
        + '<td>' + escape(r.out_iface || '—') + '</td>'
        + '<td>' + escape(r.src || '—') + '</td>'
        + '<td>' + escape(r.dst || '—') + '</td>'
        + '<td><button class="btn btn-small btn-danger" data-action="fw-del" data-rule="' + dataRule + '">del</button></td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="9" class="muted">no managed rules — add one above</td></tr>';

    const sysRows = [];
    (system || []).forEach(t => {
      (t.chains || []).forEach(c => {
        sysRows.push('<tr>'
          + '<td>' + escape(t.family) + '</td>'
          + '<td>' + escape(t.name) + '</td>'
          + '<td>' + escape(c.name) + '</td>'
          + '<td>' + escape(c.hook) + '</td>'
          + '<td>' + escape(c.type) + '</td>'
          + '<td>' + c.rules + '</td>'
          + '</tr>');
      });
    });
    document.getElementById('fw-system-body').innerHTML =
      sysRows.join('') || '<tr><td colspan="6" class="muted">no nftables tables loaded</td></tr>';
  }

  function renderNAT(rows) {
    document.getElementById('nat-body').innerHTML = (rows || []).map(n =>
      '<tr>'
      + '<td>' + escape(n.proto.toUpperCase()) + '</td>'
      + '<td>' + n.wan_port + '</td>'
      + '<td>' + escape(n.lan_ip) + '</td>'
      + '<td>' + n.lan_port + '</td>'
      + '<td><button class="btn btn-small btn-danger" data-action="nat-del" data-proto="' + escape(n.proto) + '" data-port="' + n.wan_port + '">del</button></td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="5" class="muted">no port forwards configured</td></tr>';
  }

  function renderTCPDump(rows) {
    document.getElementById('td-body').innerHTML = (rows || []).map(j => {
      const stateCls = j.state === 'running' ? 'status-pill on' : j.state === 'failed' ? 'status-pill off' : 'status-pill';
      const stopBtn = j.state === 'running'
        ? '<button class="btn btn-small" data-action="td-stop" data-id="' + escape(j.id) + '">stop</button>'
        : '<button class="btn btn-small btn-danger" data-action="td-remove" data-id="' + escape(j.id) + '">remove</button>';
      return '<tr>'
        + '<td><b>' + escape(j.id) + '</b></td>'
        + '<td><span class="' + stateCls + '">' + escape(j.state) + '</span></td>'
        + '<td>' + escape(j.iface) + '</td>'
        + '<td>' + fmtBytes(j.bytes) + '</td>'
        + '<td><code>' + escape(j.filter || 'any') + '</code></td>'
        + '<td title="' + escape(j.output_path) + '"><code>' + escape(shortenMid(j.output_path, 40)) + '</code></td>'
        + '<td>' + stopBtn + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="7" class="muted">no captures yet — start one above</td></tr>';
  }

  function renderAlerts(rows) {
    const filter = (val('alert-filter') || '').toLowerCase();
    const filtered = (rows || []).filter(a => !filter || a.message.toLowerCase().includes(filter));
    // Newest first.
    document.getElementById('alerts-body').innerHTML = filtered.slice().reverse().map(a =>
      '<tr>'
      + '<td>' + escape(a.ts) + '</td>'
      + '<td><span class="severity severity-' + escape(a.severity) + '">' + escape(a.severity) + '</span></td>'
      + '<td>' + escape(a.message) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="3" class="muted">no alerts</td></tr>';
  }

  function renderCapture(c) {
    const pill = document.getElementById('capture-pill');
    pill.textContent = c.running ? 'capture ON' : 'capture OFF';
    pill.classList.toggle('on', c.running);
    pill.classList.toggle('off', !c.running);
    document.getElementById('capture-ifaces').textContent =
      c.running ? (c.ifaces && c.ifaces.length ? c.ifaces.join(', ') : 'auto-discover') : '';
  }

  function renderIPFIX(view) {
    const el = document.getElementById('ipfix-status');
    if (!view) { el.textContent = 'status: —'; return; }
    let line = view.enabled ? 'enabled' : 'disabled';
    if (view.dialed) line += ' · dialed ' + view.endpoint;
    if (view.last_send) line += ' · last send ' + view.last_send;
    if (view.last_err) line += ' · ERROR: ' + view.last_err;
    el.textContent = 'status: ' + line;
  }

  let settingsLoaded = false;
  function renderSettings(t) {
    if (!t) return;
    // Re-populate every refresh until the user has edited any field; once
    // edited, leave their work in place. Tracked by a "loaded" flag flipped
    // on the first non-empty snapshot.
    if (settingsLoaded) return;
    settingsLoaded = true;
    document.getElementById('s-loss').value = t.packet_loss_pct;
    document.getElementById('s-dns').value = t.dns_latency_ms;
    document.getElementById('s-jitter').value = t.jitter_ms;
    document.getElementById('s-rtt').value = t.rtt_ms;
    document.getElementById('s-retrans').value = t.retransmissions_pct;
    document.getElementById('s-cooldown').value = t.incident_cooldown_sec;
    document.getElementById('s-allow').checked = !!t.allow_netops_write;
    document.getElementById('s-sentry').value = t.sentry_dsn || '';
    document.getElementById('s-guac-url').value = t.guacamole_url || '';
    document.getElementById('s-guac-cid').value = t.guacamole_conn_id || '';
    document.getElementById('s-guac-tpl').value = t.guacamole_template || '';
    document.getElementById('s-ipfix-en').checked = !!t.ipfix_enabled;
    document.getElementById('s-ipfix-ep').value = t.ipfix_endpoint || '';
    document.getElementById('s-ipfix-int').value = t.ipfix_interval_sec || 30;
    document.getElementById('s-ipfix-dom').value = t.ipfix_domain_id || 0;
  }

  function shortenMid(s, max) {
    if (!s || s.length <= max) return s || '';
    const keep = Math.floor((max - 1) / 2);
    return s.slice(0, keep) + '…' + s.slice(s.length - (max - 1 - keep));
  }

  // ---- Refresh loop ----
  let refreshing = false;
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const snap = await api('/api/snapshot');
      if (!snap) return;
      document.getElementById('session-id').textContent = snap.session || '—';
      document.getElementById('uptime').textContent = snap.uptime || '—';
      renderGrade(snap.grade || {});
      renderBandwidth(snap.bandwidth || []);
      renderTalkers(snap.top_hosts, snap.top_processes, snap.top_services);
      renderSparks('icmp-sparks', snap.latency_series || {}, '#58a6ff');
      renderSparks('dns-sparks',  snap.dns_series || {}, '#a371f7');
      renderTargets(snap.targets);
      renderDNS(snap.dns);
      renderFlows(snap.flows);
      renderDevices(snap.devices);
      renderIfaces(snap.ifaces);
      renderRoutes(snap.routes);
      renderFirewall(snap.filter_rules, snap.firewall);
      renderNAT(snap.nat);
      renderTCPDump(snap.tcpdump);
      renderAlerts(snap.anomalies);
      renderCapture(snap.capture || { running: false, ifaces: [] });
      renderIPFIX(snap.ipfix);
      renderSettings(snap.thresholds);
    } catch (e) {
      console.error('refresh failed', e);
    } finally {
      refreshing = false;
    }
  }

  // Live-update text filters without re-fetching.
  document.getElementById('flow-filter').addEventListener('input', () => refresh());
  document.getElementById('alert-filter').addEventListener('input', () => refresh());

  document.getElementById('logout').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
  });

  refresh();
  setInterval(refresh, 2000);
})();
