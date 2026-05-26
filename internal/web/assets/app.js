// Testudo web UI - single-page app with full feature parity to the TUI.
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
    // History is opt-in: don't bake its query into the 2s snapshot loop.
    // Load it lazily when the tab is shown.
    if (target === 'history') loadHistory();
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
          : btn.dataset.ip + ' - no connection ports open');
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

      // History tab - read-only browse of past sessions.
      case 'history-refresh':
        await loadHistory();
        break;
      case 'history-open':
        await openHistorySession(btn.dataset.id);
        break;
      case 'history-snapshot':
        await inspectSnapshot(btn.dataset.id);
        break;
      case 'history-inspect-close':
        document.getElementById('history-inspect-card').hidden = true;
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
    if (!us) return '-';
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
    const hasData = g.has_data !== false;
    badge.textContent = hasData ? (g.letter || '-') : '?';
    badge.className = 'grade-badge ' + (hasData ? gradeLetter(g.score || 0) : 'nodata');
    document.getElementById('grade-score').textContent = hasData ? (g.score || 0) : 'no data';
    document.getElementById('grade-verdict').textContent = g.verdict || '-';
    const bars = document.getElementById('grade-bars');
    // Sub-scores listed in g.no_data produced no measurements yet -
    // render them violet so the operator can see they were excluded
    // from the overall grade instead of contributing a fake 100.
    const noData = new Set(g.no_data || []);
    const rows = [
      ['Loss',   g.loss_score],
      ['RTT',    g.rtt_score],
      ['Jitter', g.jitter_score],
      ['DNS',    g.dns_score],
    ];
    bars.innerHTML = rows.map(([label, score]) => {
      if (noData.has(label)) {
        return '<div class="grade-bar">'
          + '<span>' + escape(label) + '</span>'
          + '<div class="grade-bar-track"><div class="grade-bar-fill" style="width:100%;background:var(--accent-violet)"></div></div>'
          + '<span class="grade-bar-value" style="color:var(--accent-violet)">no data</span>'
          + '</div>';
      }
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
    }).join('') || '<tr><td colspan="6" class="muted">no flows yet - start capture</td></tr>';

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
      + '<td>' + (s.port || '-') + '</td>'
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
      const last = vals.length ? vals[vals.length - 1].toFixed(1) + 'ms' : '-';
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
      + '<td>' + escape(f.process || '-') + '</td>'
      + '<td>' + escape(f.a) + '</td>'
      + '<td>' + escape(f.b) + '</td>'
      + '<td>' + escape(f.service || '-') + '</td>'
      + '<td>' + escape(f.dns || '-') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="9" class="muted">no flows; start capture in this tab</td></tr>';

    document.getElementById('flows-body-dash').innerHTML = (rows || []).slice(0, 5).map(f =>
      '<tr>'
      + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
      + '<td>' + escape(f.iface) + '</td>'
      + '<td>' + escape(f.process || '-') + '</td>'
      + '<td>' + escape(f.a) + '</td>'
      + '<td>' + escape(f.b) + '</td>'
      + '<td>' + escape(f.service || '-') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="8" class="muted">…awaiting flows</td></tr>';
  }

  function renderDevices(rows) {
    document.getElementById('devices-body').innerHTML = (rows || []).map(d => {
      const ports = (d.open_ports || []).length
        ? (d.open_ports || []).map(p => '<code>' + p + '</code>').join(' ')
        : '<span class="muted">-</span>';
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
        + '<td>' + escape(d.hostname || '-') + '</td>'
        + '<td>' + escape(d.vendor || '-') + '</td>'
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
    // Fallback: any port that's open and not strictly mapped - empty so
    // the connect builder uses its protocol default.
    return '';
  }

  // wifiBadge renders a per-interface mini-status used in the iface
  // table. Wireless rows show signal/SSID inline; non-wireless rows
  // render a dim "-" so the column doesn't shift width.
  function wifiBadge(iface, wifiByIface) {
    const w = wifiByIface[iface];
    if (!w) return '<span class="muted">-</span>';
    if (!w.associated) return '<span class="status-pill warn">unassoc</span>';
    let sigClass = 'on';
    if (w.signal_dbm < -85) sigClass = 'off';
    else if (w.signal_dbm < -75) sigClass = 'warn';
    const sig = w.signal_dbm ? Math.round(w.signal_dbm) + 'dBm' : 'assoc';
    const ssid = w.ssid ? ' · ' + escape(w.ssid) : '';
    return '<span class="status-pill ' + sigClass + '">' + sig + '</span>' + ssid;
  }

  // ifaceTypeBadge classifies the interface so an operator can tell at
  // a glance whether they are looking at a wireless / loopback /
  // virtual / wired NIC. The heuristic is name-based (the kernel
  // doesn't expose a "type" field on the link itself) but matches
  // every standard udev naming scheme we have seen.
  function ifaceTypeBadge(i) {
    if (i.is_wireless) return '<span class="iface-type wifi">wifi</span>';
    const n = i.name;
    if (n === 'lo') return '<span class="iface-type lo">loopback</span>';
    if (/^(docker|br-|virbr|veth|cni|flannel|cilium|kube)/.test(n)) {
      return '<span class="iface-type virt">container</span>';
    }
    if (/^(tun|tap|wg|gre|sit|ipsec|nordlynx)/.test(n)) {
      return '<span class="iface-type vpn">tunnel</span>';
    }
    if (/^(en|eth)/.test(n)) return '<span class="iface-type wired">wired</span>';
    if (/^(wl|wlan)/.test(n)) return '<span class="iface-type wifi">wifi</span>';
    return '<span class="iface-type virt">virtual</span>';
  }

  function fmtCount(n) {
    return n > 0 ? '<b class="warn">' + n + '</b>' : String(n || 0);
  }

  function renderIfaces(rows, wifi) {
    const wifiByIface = {};
    (wifi || []).forEach(w => { wifiByIface[w.iface] = w; });
    document.getElementById('ifaces-body').innerHTML = (rows || []).map(i => {
      const state = i.up
        ? '<span class="status-pill on">UP</span>'
        : '<span class="status-pill off">DOWN</span>';
      const n = escape(i.name);
      return '<tr>'
        + '<td><b>' + n + '</b></td>'
        + '<td>' + state + '</td>'
        + '<td>' + ifaceTypeBadge(i) + '</td>'
        + '<td>' + i.mtu + '</td>'
        + '<td class="mono">' + escape(i.hw) + '</td>'
        + '<td>' + (i.addrs || []).map(escape).join(', ') + '</td>'
        + '<td>' + fmtBytes(i.rx_bytes) + '</td>'
        + '<td>' + fmtBytes(i.tx_bytes) + '</td>'
        + '<td>' + fmtCount(i.rx_errors) + '</td>'
        + '<td>' + fmtCount(i.tx_errors) + '</td>'
        + '<td>' + fmtCount((i.rx_dropped || 0) + (i.tx_dropped || 0)) + '</td>'
        + '<td>' + fmtCount(i.collisions) + '</td>'
        + '<td>' + wifiBadge(i.name, wifiByIface) + '</td>'
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
    }).join('') || '<tr><td colspan="14" class="muted">no interfaces visible</td></tr>';
  }

  // renderWiFi renders one card per wireless interface on the
  // Dashboard. Empty when the host has no wifi NICs, otherwise the
  // operator sees SSID / BSSID / channel / signal / bitrate /
  // station-level counters for every radio the collector reports.
  function renderWiFi(rows) {
    const host = document.getElementById('wifi-list');
    if (!host) return;
    if (!rows || rows.length === 0) {
      host.innerHTML = '<div class="muted">no wireless interfaces detected (no NICs under /sys/class/net/*/wireless)</div>';
      return;
    }
    host.innerHTML = rows.map(w => {
      const headerClass = w.associated ? 'wifi-card' : 'wifi-card idle';
      const sigClass = !w.associated || w.signal_dbm === 0 ? 'muted'
        : (w.signal_dbm < -85 ? 'err' : (w.signal_dbm < -75 ? 'warn' : 'ok'));
      const lines = [];
      lines.push('<div class="wifi-head"><b>' + escape(w.iface) + '</b> '
        + (w.associated
            ? '<span class="status-pill on">associated</span>'
            : '<span class="status-pill warn">unassociated</span>')
        + ' <span class="muted">' + escape(w.hw_addr || '-') + '</span>'
        + (w.source ? ' <span class="muted">(' + escape(w.source) + ')</span>' : '')
        + '</div>');
      if (!w.associated) {
        lines.push('<div class="muted">radio is up but not joined to an AP — no SSID / channel / bitrate data</div>');
        return '<div class="' + headerClass + '">' + lines.join('') + '</div>';
      }
      lines.push('<dl class="wifi-grid">');
      lines.push('<dt>SSID</dt><dd>' + escape(w.ssid || '(unknown)') + '</dd>');
      lines.push('<dt>BSSID</dt><dd class="mono">' + escape(w.bssid || '-') + '</dd>');
      if (w.frequency_mhz > 0) {
        const ch = w.channel_width_mhz > 0
          ? (w.channel + ' (' + w.channel_width_mhz + ' MHz wide)')
          : String(w.channel);
        lines.push('<dt>Channel</dt><dd>' + escape(ch) + ' · ' + w.frequency_mhz + ' MHz · ' + escape(w.band) + '</dd>');
      }
      const sigParts = [];
      if (w.signal_dbm) sigParts.push('<span class="' + sigClass + '">' + Math.round(w.signal_dbm) + ' dBm</span>');
      if (w.signal_avg_dbm && w.signal_avg_dbm !== w.signal_dbm) sigParts.push('avg ' + Math.round(w.signal_avg_dbm));
      if (w.noise_dbm) sigParts.push('noise ' + Math.round(w.noise_dbm) + ' · SNR ' + Math.round(w.signal_dbm - w.noise_dbm) + ' dB');
      lines.push('<dt>Signal</dt><dd>' + sigParts.join(' · ') + '</dd>');
      if (w.tx_bitrate_mbps > 0 || w.rx_bitrate_mbps > 0) {
        lines.push('<dt>Bitrate</dt><dd>tx ' + w.tx_bitrate_mbps.toFixed(1) + ' Mbit/s · rx ' + w.rx_bitrate_mbps.toFixed(1) + ' Mbit/s</dd>');
      }
      if (w.tx_power_dbm > 0) {
        lines.push('<dt>TX power</dt><dd>' + w.tx_power_dbm.toFixed(1) + ' dBm</dd>');
      }
      if (w.link_quality > 0) {
        const max = w.link_quality_max || 70;
        const pct = Math.round(w.link_quality / max * 100);
        lines.push('<dt>Quality</dt><dd>' + w.link_quality + '/' + max + ' (' + pct + '%)</dd>');
      }
      lines.push('<dt>Counters</dt><dd>retries ' + (w.retries || 0)
        + ' · tx-failed ' + fmtCount(w.tx_failed)
        + ' · beacon-loss ' + fmtCount(w.beacon_loss) + '</dd>');
      if (w.rx_bytes + w.tx_bytes > 0) {
        lines.push('<dt>Station</dt><dd>rx ' + fmtBytes(w.rx_bytes) + ' (' + w.rx_packets + ' pkts) · tx ' + fmtBytes(w.tx_bytes) + ' (' + w.tx_packets + ' pkts)</dd>');
      }
      if (w.connected_for) {
        lines.push('<dt>Up since</dt><dd>' + escape(w.connected_for) + ' ago</dd>');
      }
      lines.push('</dl>');
      return '<div class="' + headerClass + '">' + lines.join('') + '</div>';
    }).join('');
  }

  function renderRoutes(rows) {
    document.getElementById('routes-body').innerHTML = (rows || []).map(r =>
      '<tr>'
      + '<td>' + escape(r.family) + '</td>'
      + '<td>' + escape(r.dst) + '</td>'
      + '<td>' + escape(r.gateway || '-') + '</td>'
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
        + '<td>' + escape(r.proto.toUpperCase() || '-') + '</td>'
        + '<td>' + (r.port || '-') + '</td>'
        + '<td>' + escape(r.in_iface || '-') + '</td>'
        + '<td>' + escape(r.out_iface || '-') + '</td>'
        + '<td>' + escape(r.src || '-') + '</td>'
        + '<td>' + escape(r.dst || '-') + '</td>'
        + '<td><button class="btn btn-small btn-danger" data-action="fw-del" data-rule="' + dataRule + '">del</button></td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="9" class="muted">no managed rules - add one above</td></tr>';

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
    }).join('') || '<tr><td colspan="7" class="muted">no captures yet - start one above</td></tr>';
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
    if (!view) { el.textContent = 'status: -'; return; }
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

  // ---- History tab ---------------------------------------------------
  // The history view is opt-in (loaded when the tab is clicked or the
  // user hits Refresh). It does NOT join the 2s snapshot poll because
  // past sessions don't change between page loads.
  function escapeHTML(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmtDuration(ms) {
    if (!ms || ms <= 0) return 'running';
    const s = Math.round(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60), rem = s % 60;
    if (m < 60) return m + 'm ' + rem + 's';
    const h = Math.floor(m / 60);
    return h + 'h ' + (m % 60) + 'm';
  }
  function shortID(s) {
    if (!s) return '-';
    return s.length > 12 ? s.slice(0, 8) + '…' : s;
  }

  async function loadHistory() {
    const status = document.getElementById('history-status');
    const body = document.getElementById('history-body');
    status.textContent = 'loading…';
    try {
      const list = await api('/api/sessions');
      if (!Array.isArray(list) || list.length === 0) {
        body.innerHTML = '<tr><td colspan="6" class="muted">no sessions persisted yet</td></tr>';
        status.textContent = '0 sessions';
        return;
      }
      body.innerHTML = list.map(s => {
        const targets = (s.targets || []).join(', ');
        return '<tr>'
          + '<td><code>' + escapeHTML(shortID(s.id)) + '</code></td>'
          + '<td>' + escapeHTML(s.started_at || '') + '</td>'
          + '<td>' + escapeHTML(s.ended_at || '-') + '</td>'
          + '<td>' + escapeHTML(fmtDuration(s.duration_ms)) + '</td>'
          + '<td>' + escapeHTML(targets) + '</td>'
          + '<td><button class="btn" data-action="history-open" data-id="'
          + escapeHTML(s.id) + '">Open</button></td>'
          + '</tr>';
      }).join('');
      status.textContent = list.length + ' session(s)';
    } catch (e) {
      status.textContent = 'error: ' + (e.message || e);
    }
  }

  async function openHistorySession(id) {
    if (!id) return;
    const card = document.getElementById('history-detail-card');
    const title = document.getElementById('history-detail-title');
    const meta = document.getElementById('history-detail-meta');
    const aBody = document.getElementById('history-anomalies-body');
    const sBody = document.getElementById('history-snapshots-body');
    const inspect = document.getElementById('history-inspect-card');
    inspect.hidden = true;
    card.hidden = false;
    title.textContent = 'Session ' + id;
    meta.textContent = 'loading…';
    aBody.innerHTML = '';
    sBody.innerHTML = '';
    try {
      const d = await api('/api/session/detail?id=' + encodeURIComponent(id));
      if (!d) return;
      meta.innerHTML =
        '<b>started:</b> ' + escapeHTML(d.started_at) +
        ' &nbsp; <b>ended:</b> ' + escapeHTML(d.ended_at || '(running)') +
        ' &nbsp; <b>duration:</b> ' + escapeHTML(fmtDuration(d.duration_ms)) +
        ' &nbsp; <b>targets:</b> ' + escapeHTML((d.targets || []).join(', ') || '-') +
        ' &nbsp; <b>counts:</b> ' + (d.anomalies || []).length + ' anomalies · '
        + (d.snapshots || []).length + ' snapshots';

      const anomalies = d.anomalies || [];
      aBody.innerHTML = anomalies.length === 0
        ? '<tr><td colspan="3" class="muted">no anomalies recorded for this session</td></tr>'
        : anomalies.map(a => '<tr>'
            + '<td>' + escapeHTML(a.ts) + '</td>'
            + '<td><span class="severity severity-' + escapeHTML(a.severity || '')
            + '">' + escapeHTML(a.severity) + '</span></td>'
            + '<td>' + escapeHTML(a.message) + '</td>'
            + '</tr>').join('');

      const snaps = d.snapshots || [];
      sBody.innerHTML = snaps.length === 0
        ? '<tr><td colspan="4" class="muted">no snapshots captured for this session</td></tr>'
        : snaps.map(e => '<tr>'
            + '<td><code>' + e.id + '</code></td>'
            + '<td>' + escapeHTML(e.kind) + '</td>'
            + '<td>' + escapeHTML(e.ts) + '</td>'
            + '<td><button class="btn" data-action="history-snapshot" data-id="'
            + e.id + '">Inspect</button></td>'
            + '</tr>').join('');
    } catch (e) {
      meta.textContent = 'error: ' + (e.message || e);
    }
  }

  async function inspectSnapshot(id) {
    if (!id) return;
    const card = document.getElementById('history-inspect-card');
    const title = document.getElementById('history-inspect-title');
    const body = document.getElementById('history-inspect-body');
    card.hidden = false;
    title.textContent = 'Snapshot #' + id + ' - loading…';
    body.textContent = '';
    try {
      const r = await api('/api/session/snapshot?id=' + encodeURIComponent(id));
      if (!r) return;
      title.textContent = 'Snapshot #' + r.id + ' · ' + r.kind + ' · ' + r.ts;
      body.textContent = r.payload || '(empty payload)';
    } catch (e) {
      body.textContent = 'error: ' + (e.message || e);
    }
  }

  // ---- Refresh loop ----
  let refreshing = false;
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const snap = await api('/api/snapshot');
      if (!snap) return;
      document.getElementById('session-id').textContent = snap.session || '-';
      document.getElementById('uptime').textContent = snap.uptime || '-';
      renderGrade(snap.grade || {});
      renderBandwidth(snap.bandwidth || []);
      renderTalkers(snap.top_hosts, snap.top_processes, snap.top_services);
      renderSparks('icmp-sparks', snap.latency_series || {}, '#58a6ff');
      renderSparks('dns-sparks',  snap.dns_series || {}, '#a371f7');
      renderTargets(snap.targets);
      renderDNS(snap.dns);
      renderFlows(snap.flows);
      renderDevices(snap.devices);
      renderIfaces(snap.ifaces, snap.wifi);
      renderWiFi(snap.wifi);
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
