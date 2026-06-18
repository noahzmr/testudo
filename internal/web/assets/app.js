// Testudo web UI - single-page app with full feature parity to the TUI.
// All mutations POST JSON to /api/<feature>/<verb>; the snapshot endpoint
// returns the unified state that drives every read view.
(function () {
  'use strict';

  // ---- Tab switching ----
  const tabs = document.querySelectorAll('.tab');
  const panes = document.querySelectorAll('.pane');
  const viewTitle = document.getElementById('view-title');
  tabs.forEach(btn => btn.addEventListener('click', () => {
    tabs.forEach(b => {
      const on = b === btn;
      b.classList.toggle('active', on);
      // aria-current marks the active nav item for assistive tech.
      if (on) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    const target = btn.dataset.tab;
    panes.forEach(p => p.classList.toggle('active', p.dataset.pane === target));
    // Reflect the active view in the content topbar (label = nav text).
    if (viewTitle) viewTitle.textContent = btn.textContent.trim();
    // On the mobile drawer, picking a destination closes the nav.
    closeNav();
    // History is opt-in: don't bake its query into the 2s snapshot loop.
    // Load it lazily when the tab is shown.
    if (target === 'history') loadHistory();
  }));

  // ---- Mobile nav drawer (sidebar collapses below 1080px) ----
  const navToggle = document.getElementById('nav-toggle');
  const scrim = document.getElementById('scrim');
  function closeNav() {
    document.body.classList.remove('nav-open');
    if (navToggle) navToggle.setAttribute('aria-expanded', 'false');
  }
  if (navToggle) {
    navToggle.addEventListener('click', () => {
      const open = document.body.classList.toggle('nav-open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }
  if (scrim) scrim.addEventListener('click', closeNav);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeNav(); });

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
      case 'fw-reset': {
        if (!confirm('Reset counter on ' + btn.dataset.table + '/' + btn.dataset.chain + ' handle ' + btn.dataset.handle + '?')) return;
        await post('/api/firewall/reset-counter', {
          family: btn.dataset.family,
          table:  btn.dataset.table,
          chain:  btn.dataset.chain,
          handle: parseInt(btn.dataset.handle, 10),
        });
        showToast('counter reset');
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
      case 'ct-flush': {
        const f = JSON.parse(btn.dataset.flow);
        if (!confirm('Flush ' + f.proto + ' flow ' + f.orig_src + ':' + f.orig_sport + ' -> ' + f.orig_dst + ':' + f.orig_dport + '?')) return;
        await post('/api/conntrack/flush', {
          proto: f.proto,
          orig_src: f.orig_src,
          orig_dst: f.orig_dst,
          orig_sport: f.orig_sport,
          orig_dport: f.orig_dport,
          natted: f.natted,
        });
        showToast('conntrack flow flushed');
        break;
      }
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
      case 'device-nmap-scan': {
        const target = val('nmap-target');
        if (!target) { showToast('enter an IP or CIDR to scan'); break; }
        showToast('nmap scanning ' + target + '… (this can take a minute)');
        btn.disabled = true;
        try {
          const r = await post('/api/device/nmap-scan', { target });
          const n = (r && r.discovered) || 0;
          showToast(n
            ? 'nmap found ' + n + ' host' + (n === 1 ? '' : 's') + ' on ' + target
            : 'nmap found no hosts on ' + target);
          await refresh();
        } catch (e) {
          showToast('nmap scan failed: ' + e.message);
        } finally {
          btn.disabled = false;
        }
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
      case 'baseline-reset':
        try {
          const r = await post('/api/baseline/reset', {});
          showToast('baseline reset for ' + (r && r.reset != null ? r.reset : 0) + ' target(s)');
        } catch (e) {
          showToast('baseline reset failed: ' + e.message);
        }
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
      expected_down_mbps:   parseFloat(val('s-expdown')) || 0,
      expected_up_mbps:     parseFloat(val('s-expup')) || 0,
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
  // ipBadge renders the routability classification from snapshot ipLabel
  // ({scope, class, detail}) as an inline pill, mirroring the TUI's scope·class
  // tag. Returns '' for an absent/unknown label so callers can append blindly.
  const SCOPE_SHORT = { public: 'pub', private: 'prv', internal: 'int', multicast: 'mcast' };
  function ipBadge(l) {
    if (!l || !l.scope) return '';
    let txt = SCOPE_SHORT[l.scope] || '?';
    if (l.class) txt += '·' + l.class;
    const title = l.detail ? l.scope + ' · ' + l.detail : l.scope;
    return '<span class="ipbadge ipbadge-' + escape(l.scope) + '" title="' + escape(title) + '">'
      + escape(txt) + '</span>';
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
  // Negotiated link speed (decimal, like ethtool / sysfs).
  function fmtMbps(mbps) {
    if (!mbps || mbps <= 0) return '-';
    if (mbps >= 1000) {
      const g = mbps / 1000;
      return (g % 1 === 0 ? g.toFixed(0) : g.toFixed(1)) + ' Gbps';
    }
    return mbps + ' Mbps';
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
  // GRADE_HELP describes each Network Quality sub-score: what it measures and
  // how the value is derived. Surfaced as a hover/focus tooltip on each bar.
  const GRADE_HELP = {
    Loss:       'Packet loss, worse of two sources: ICMP/probe loss over the last 30 results, and the TCP retransmission rate (a retransmit is a lost segment). ICMP echo often survives a path that drops or resets TCP, so probe loss alone is optimistic - the worse figure is used. Threshold: your Packet-loss setting.',
    RTT:        'WAN round-trip latency. Mean RTT of recent probes to external targets, sharpened by the worst active TCP flow. Threshold: your RTT setting.',
    Jitter:     'Latency variation - the mean change between consecutive RTT samples. High jitter degrades VoIP/video/gaming. Threshold: your Jitter setting.',
    DNS:        'Resolver health. Blends DNS query latency with the failure/timeout rate across probed resolvers, so timeouts count even when nothing resolves. Threshold: DNS-latency setting + 5% failures.',
    LAN:        'LAN reachability. Blends loss and RTT to LAN hosts (50 ms comfort) and hard-penalises any active duplicate-IP (ARP) conflict.',
    HTTP:       'Service health of configured HTTP endpoints. Blends time-to-first-byte (500 ms comfort) with the request failure/timeout rate (2% comfort).',
    Stab:       'Interface stability. Kernel error/drop ratio, unreachable-neighbour ratio, and link-flap / default-route churn from the netlink watcher (2/min comfort).',
    WiFi:       'Wireless link quality across associated radios. Blends RSSI (−60 dBm great, −90 unusable), signal-to-noise ratio, and the TX-failure rate - so a strong signal that keeps failing still scores low.',
    NAT:        'Connection-tracking pressure. Live conntrack entries ÷ nf_conntrack_max; near saturation new connections fail host-wide (70% comfort).',
    Congestion: 'Per-flow TCP retransmission rate from tcp_info (INET_DIAG/eBPF), byte-weighted so busy flows dominate. Threshold: your Retransmissions setting.',
    Throughput: 'Achievable speed. The best download/upload observed recently (while transferring) vs your configured expected link speed; reaching ~90% of the rated speed scores 100. Set Expected down/up in Settings - left unset or idle, this dimension shows no data. (Firewall DROP velocity is intentionally not part of the grade - a blocked packet is policy, not quality.)',
  };
  // GRADE_SCORING is appended to every tooltip: the shared 0–100 mapping.
  const GRADE_SCORING = ' - Scored 100 at zero, 50 at the comfort threshold, 0 at twice the threshold. Dimensions with no measurements yet are excluded from the overall grade.';

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
      ['Loss',       g.loss_score],
      ['RTT',        g.rtt_score],
      ['Throughput', g.throughput_score],
      ['Congestion', g.congestion_score],
      ['DNS',        g.dns_score],
      ['LAN',        g.lan_score],
      ['Stab',       g.stab_score],
      ['Jitter',     g.jitter_score],
      ['HTTP',       g.http_score],
      ['WiFi',       g.wifi_score],
      ['NAT',        g.nat_score],
    ];
    bars.innerHTML = rows.map(([label, score]) => {
      let tip = escape(GRADE_HELP[label] || '') + GRADE_SCORING;
      if (label === 'Loss' && g.loss_has_tcp) {
        tip += escape(' - now: ICMP ' + (g.loss_icmp_pct || 0).toFixed(1) + '%, TCP retrans '
          + (g.loss_tcp_pct || 0).toFixed(1) + '%, conn-fail ' + (g.loss_conn_fail_rate || 0).toFixed(1) + '/s.');
      }
      const attrs = ' data-tip="' + tip + '" tabindex="0"';
      if (noData.has(label)) {
        return '<div class="grade-bar"' + attrs + '>'
          + '<span>' + escape(label) + '</span>'
          + '<div class="grade-bar-track"><div class="grade-bar-fill" style="width:100%;background:var(--accent-violet)"></div></div>'
          + '<span class="grade-bar-value" style="color:var(--accent-violet)">no data</span>'
          + '</div>';
      }
      const color = score >= 85 ? '#3fb950'
                 : score >= 70 ? '#d29922'
                 : score >= 60 ? '#db6d28'
                 :              '#f85149';
      return '<div class="grade-bar"' + attrs + '>'
        + '<span>' + escape(label) + '</span>'
        + '<div class="grade-bar-track"><div class="grade-bar-fill" style="width:' + (score || 0) + '%;background:' + color + '"></div></div>'
        + '<span class="grade-bar-value">' + (score || 0) + '</span>'
        + '</div>';
    }).join('');
    renderQualityContext(g);
    // Self-health badge: a degraded core signal collector means the grade is
    // measured with reduced coverage - flag it so an A isn't read as "all good".
    const sh = document.getElementById('grade-selfhealth');
    if (sh) {
      if (g.self_health_degraded) {
        sh.textContent = '⚠ measuring with reduced coverage';
        sh.className = 'grade-selfhealth warn';
      } else if (g.self_health_state && g.self_health_state !== 'ok') {
        sh.textContent = '· some subsystems degraded';
        sh.className = 'grade-selfhealth muted';
      } else {
        sh.textContent = '';
        sh.className = 'grade-selfhealth';
      }
    }
  }

  // renderHealth renders the subsystem-status table, the privilege-separation
  // posture, and the read-only audit log of privileged mutations (mirrors the
  // TUI Health tab). The web server itself is unprivileged - the privsep line
  // states it explicitly.
  function renderHealth(subsystems, audit, privsep) {
    const info = document.getElementById('privsep-info');
    if (info) info.textContent = privsep || '';

    const sbody = document.getElementById('subsystems-body');
    if (sbody) {
      const stateClass = s => s === 'ok' ? 'ok'
        : s === 'failed' ? 'err'
        : 'warn';
      sbody.innerHTML = (subsystems || []).map(s => {
        const detail = (s.state === 'unprivileged' && s.hint) ? s.hint : (s.last_err || '-');
        return '<tr>'
          + '<td>' + escape(s.name) + (s.core ? ' <span class="muted">(core)</span>' : '') + '</td>'
          + '<td class="' + stateClass(s.state) + '">' + escape(s.state) + '</td>'
          + '<td>' + (s.restarts || 0) + '</td>'
          + '<td>' + escape(detail) + '</td>'
          + '</tr>';
      }).join('') || '<tr><td colspan="4" class="muted">no subsystems registered yet</td></tr>';
    }

    const abody = document.getElementById('audit-body');
    if (abody) {
      abody.innerHTML = (audit || []).map(e => {
        const ok = (e.result === 'ok' || !e.result);
        return '<tr>'
          + '<td>' + escape(e.ts || '-') + '</td>'
          + '<td>' + escape(e.op) + '</td>'
          + '<td>' + (e.peer_uid || 0) + '</td>'
          + '<td class="' + (ok ? 'ok' : 'err') + '">' + escape(ok ? 'ok' : e.result) + '</td>'
          + '</tr>';
      }).join('') || '<tr><td colspan="4" class="muted">no privileged mutations recorded</td></tr>';
    }
  }

  // renderQualityContext renders the baseline early-warning, bufferbloat letter,
  // and ISP-isolation verdict beneath the grade bars (mirrors the TUI card).
  function renderQualityContext(g) {
    const el = document.getElementById('grade-context');
    if (!el) return;
    const lines = [];
    if (g.has_baseline) {
      const r = (g.baseline_ratio || 0).toFixed(1);
      if (g.baseline_penalty > 0) {
        lines.push('<div class="grade-ctx warn">Baseline: ' + r + '× normal &#9650; (grade &minus;' + g.baseline_penalty + ', early warning)</div>');
      } else if (g.baseline_ratio <= 0.66) {
        lines.push('<div class="grade-ctx ok">Baseline: ' + r + '× normal &#9660; (better than usual)</div>');
      } else {
        lines.push('<div class="grade-ctx muted">Baseline: ' + r + '× normal (&#8776; usual for this hour)</div>');
      }
    }
    if (g.has_bufferbloat) {
      const cls = bufferbloatClass(g.bufferbloat_grade);
      lines.push('<div class="grade-ctx">Bufferbloat: <span class="bb-grade ' + cls + '">' + escape(g.bufferbloat_grade) + '</span> <span class="muted">(idle-vs-loaded latency)</span></div>');
    }
    if (g.has_fault) {
      const cls = (g.fault_layer && g.fault_layer !== 'none') ? 'warn' : 'ok';
      lines.push('<div class="grade-ctx ' + cls + '">' + escape(g.fault_verdict || '') + '</div>');
    }
    // Active-traffic connection faults (mirror the TUI dashboard penalty lines).
    if (g.pmtu_blackhole) {
      lines.push('<div class="grade-ctx bad">&#9888; PMTU black-hole detected (&minus;' + (g.pmtu_penalty || 0) + ') &mdash; a flow is retransmitting without progress</div>');
    }
    if (g.connect_stall) {
      lines.push('<div class="grade-ctx bad">&#9888; ' + (g.stalled_connects || 0) + ' connection(s) failing to establish (&minus;' + (g.connect_penalty || 0) + ') &mdash; stuck in TCP handshake (SYN_SENT)</div>');
    }
    if (g.conn_reset_spike) {
      lines.push('<div class="grade-ctx bad">&#9888; connections dropping at ' + (g.conn_reset_rate || 0).toFixed(1) + '/s (&minus;' + (g.reset_penalty || 0) + ') &mdash; refused/failed connects + resets</div>');
    }
    if (g.send_stall) {
      lines.push('<div class="grade-ctx warn">&#9888; ' + (g.send_stalls || 0) + ' connection(s) send-stalled (&minus;' + (g.stall_penalty || 0) + ') &mdash; peer zero-window or path blocked</div>');
    }
    if (g.ephemeral_exhaustion) {
      lines.push('<div class="grade-ctx bad">&#9888; ephemeral ports ' + ((g.ephemeral_util || 0) * 100).toFixed(0) + '% used (&minus;' + (g.ephemeral_penalty || 0) + ') &mdash; new outbound connections may start failing</div>');
    }
    el.innerHTML = lines.join('');
  }

  function bufferbloatClass(letter) {
    if (letter === 'A' || letter === 'A+' || letter === 'A-') return 'ok';
    if (letter === 'B' || letter === 'B+') return 'warn';
    if (letter === 'C') return 'warn';
    return 'bad';
  }

  // ---- Dashboard KPI strip --------------------------------------------
  // Aggregates snapshot fields into four compact rows of headline metrics.
  // Each tile picks its own ok/warn/err state so degradation is visible
  // without reading the numbers.
  function kpiTile(label, value, opts) {
    opts = opts || {};
    const state = opts.state ? ' ' + opts.state : '';
    const arrow = opts.arrow
      ? '<span class="kpi-arrow ' + opts.arrow + '">' + (opts.arrow === 'down' ? '&darr;' : '&uarr;') + '</span>'
      : '';
    const sub = opts.sub ? '<div class="kpi-sub">' + opts.sub + '</div>' : '';
    return ''
      + '<div class="kpi-tile' + state + '">'
      +   '<div class="kpi-label">' + arrow + escape(label) + '</div>'
      +   '<div class="kpi-value">' + value + '</div>'
      +   sub
      + '</div>';
  }

  function renderKpis(snap) {
    const thr = snap.thresholds || {};

    // --- Network: aggregate Rx/Tx across non-loopback interfaces -------
    const bw = (snap.bandwidth || []).filter(b => b.iface !== 'lo');
    let curRx = 0, curTx = 0, peakRx = 0, peakTx = 0, cumRx = 0, cumTx = 0;
    for (const b of bw) {
      curRx  += (b.current_rx || 0);
      curTx  += (b.current_tx || 0);
      peakRx += (b.peak_rx    || 0);
      peakTx += (b.peak_tx    || 0);
      cumRx  += (b.cum_rx     || 0);
      cumTx  += (b.cum_tx     || 0);
    }
    // Negotiated link capacity of the upstream interface (the one carrying
    // the lowest-metric IPv4 default route). Summing every NIC would
    // double-count secondary NICs, USB adapters, bridges, etc.
    let uplinkIface = '';
    let uplinkMetric = Infinity;
    for (const r of (snap.routes || [])) {
      if (r.dst !== 'default') continue;
      if ((r.family || '').indexOf('6') !== -1) continue; // prefer v4
      const m = r.metric == null ? 0 : r.metric;
      if (m < uplinkMetric) { uplinkMetric = m; uplinkIface = r.iface; }
    }
    let linkMbps = 0;
    if (uplinkIface) {
      const i = (snap.ifaces || []).find(x => x.name === uplinkIface);
      if (i && (i.speed_mbps || 0) > 0) linkMbps = i.speed_mbps;
    }
    const linkSub = linkMbps > 0
      ? ' · ' + uplinkIface + ' link ' + fmtMbps(linkMbps)
      : '';
    document.getElementById('kpi-network').innerHTML = ''
      + kpiTile('Download', fmtBytes(curRx) + '/s', {
          arrow: 'down', sub: 'peak ' + fmtBytes(peakRx) + '/s' + linkSub })
      + kpiTile('Upload', fmtBytes(curTx) + '/s', {
          arrow: 'up', sub: 'peak ' + fmtBytes(peakTx) + '/s' + linkSub })
      + kpiTile('Session ↓', fmtBytes(cumRx), {
          sub: bw.length + ' iface' + (bw.length === 1 ? '' : 's') })
      + kpiTile('Session ↑', fmtBytes(cumTx), {
          sub: bw.length + ' iface' + (bw.length === 1 ? '' : 's') });

    // --- Health: live observability ------------------------------------
    const tel = snap.telemetry || {};
    const rttMs = tel.worst_rtt_ms || 0;
    const rttThr = thr.rtt_ms || 150;
    const rttState = rttMs <= 0 ? '' : (rttMs > rttThr * 2 ? 'err' : (rttMs > rttThr ? 'warn' : 'ok'));
    const rtx = tel.worst_rtx || 0;
    const rtxThr = thr.retransmissions_pct || 5;
    const rtxState = rtx <= 0 ? '' : (rtx > rtxThr * 2 ? 'err' : (rtx > rtxThr ? 'warn' : 'ok'));
    const ct = snap.conntrack || {};
    const ctUtil = (ct.max && ct.count) ? (ct.count / ct.max * 100) : 0;
    const ctState = ctUtil > 90 ? 'err' : (ctUtil > 70 ? 'warn' : '');

    // Connection-establishment / teardown health from the TCP telemetry source.
    let connVal = 'OK', connState = 'ok', connSub = 'connects healthy';
    if (tel.connect_stall) {
      connVal = (tel.stalled_conn || 0) + ' stalled'; connState = 'err'; connSub = 'stuck in handshake (SYN_SENT)';
    } else if (tel.conn_reset_spike) {
      connVal = (tel.conn_fail_rate || 0).toFixed(1) + '/s'; connState = 'err'; connSub = 'refused/failed + resets';
    } else if (tel.send_stall) {
      connVal = (tel.send_stalls || 0) + ' frozen'; connState = 'warn'; connSub = 'zero-window / path blocked';
    } else if (tel.ephemeral_exhaust) {
      connVal = (tel.ephemeral_util * 100).toFixed(0) + '% ports'; connState = 'err'; connSub = 'ephemeral near-exhaustion';
    } else if (!tel.source) {
      connVal = '-'; connState = ''; connSub = 'no telemetry';
    }

    // System clock (NTP discipline).
    const clk = snap.clock || {};
    let clkVal = '-', clkState = '', clkSub = 'disabled';
    if (clk.enabled) {
      if (!clk.synchronised) {
        clkVal = 'unsynced'; clkState = 'err'; clkSub = 'no NTP discipline';
      } else {
        const off = Math.abs(clk.offset_ms || 0);
        clkVal = (clk.offset_ms || 0).toFixed(1) + ' ms';
        clkState = off >= 100 ? 'warn' : 'ok';
        clkSub = 'offset · synced';
      }
    }

    document.getElementById('kpi-health').innerHTML = ''
      + kpiTile('Active flows', String(tel.flows || 0), {
          sub: (tel.source || '-') + (tel.ebpf_available ? ' · eBPF' : '') })
      + kpiTile('Worst RTT', rttMs > 0 ? rttMs.toFixed(1) + ' ms' : '-', {
          state: rttState, sub: 'threshold ' + rttThr + ' ms' })
      + kpiTile('Worst retrans', rtx > 0 ? rtx.toFixed(2) + ' %' : '-', {
          state: rtxState, sub: 'threshold ' + rtxThr + ' %' })
      + kpiTile('Connections', connVal, { state: connState, sub: connSub })
      + kpiTile('Conntrack', ct.max ? (ct.count || 0) + ' / ' + ct.max : '-', {
          state: ctState, sub: ct.max ? ctUtil.toFixed(1) + ' % used' : 'no data' })
      + kpiTile('System clock', clkVal, { state: clkState, sub: clkSub });

    // --- Security: blocked traffic + structural faults -----------------
    const anomalies = snap.anomalies || [];
    const sev = { CRITICAL: 0, ERROR: 0, WARN: 0, INFO: 0 };
    for (const a of anomalies) if (sev[a.severity] !== undefined) sev[a.severity]++;
    const alertState = sev.CRITICAL ? 'err' : ((sev.ERROR || sev.WARN) ? 'warn' : (anomalies.length ? '' : 'ok'));
    const alertSub = sev.CRITICAL + ' crit · ' + sev.ERROR + ' err · ' + sev.WARN + ' warn';

    let fwDropPkts = 0, fwDropBytes = 0;
    for (const r of (snap.firewall_rules || [])) {
      if (r.blocking && r.has_counter) { fwDropPkts += (r.packets || 0); fwDropBytes += (r.bytes || 0); }
    }
    const conflicts = (snap.ip_conflicts || []).length;
    const conflictState = conflicts > 0 ? 'err' : '';

    document.getElementById('kpi-security').innerHTML = ''
      + kpiTile('Open alerts', String(anomalies.length), {
          state: alertState, sub: alertSub })
      + kpiTile('Firewall drops', fmtCount(fwDropPkts), {
          state: fwDropPkts > 0 ? 'warn' : '', sub: fmtBytes(fwDropBytes) + ' blocked' })
      + kpiTile('IP conflicts', String(conflicts), {
          state: conflictState, sub: conflicts > 0 ? 'duplicate L2 owners' : 'L2 clean' })
      + kpiTile('Port forwards', String((snap.nat || []).length), {
          sub: 'active DNAT rules' });

    // --- Infrastructure: inventory & link health -----------------------
    const ifaces = (snap.ifaces || []).filter(i => i.name !== 'lo');
    let ifErr = 0, ifDrop = 0;
    for (const i of ifaces) {
      ifErr  += (i.rx_errors  || 0) + (i.tx_errors  || 0);
      ifDrop += (i.rx_dropped || 0) + (i.tx_dropped || 0);
    }
    const ifErrState = ifErr > 0 ? 'warn' : 'ok';

    let worstSig = null;
    for (const w of (snap.wifi || [])) {
      if (!w.associated || !w.signal_dbm) continue;
      if (worstSig === null || w.signal_dbm < worstSig) worstSig = w.signal_dbm;
    }
    const sigState = worstSig === null ? '' : (worstSig < -80 ? 'err' : (worstSig < -70 ? 'warn' : 'ok'));

    const subs = snap.subsystems || [];
    const degraded = subs.filter(s => s.state && s.state !== 'running' && s.state !== 'ok').length;
    const subState = degraded > 0 ? (subs.some(s => s.core && s.state !== 'running' && s.state !== 'ok') ? 'err' : 'warn') : 'ok';

    document.getElementById('kpi-infra').innerHTML = ''
      + kpiTile('Devices online', String((snap.devices || []).length), {
          sub: 'discovered hosts' })
      + kpiTile('Iface errors', fmtCount(ifErr), {
          state: ifErrState, sub: fmtCount(ifDrop) + ' drops · ' + ifaces.length + ' iface' + (ifaces.length === 1 ? '' : 's') })
      + kpiTile('WiFi signal', worstSig === null ? '-' : worstSig.toFixed(0) + ' dBm', {
          state: sigState, sub: worstSig === null ? 'no associated radio' : 'worst of associated' })
      + kpiTile('Subsystems', (subs.length - degraded) + ' / ' + subs.length, {
          state: subState, sub: degraded === 0 ? 'all running' : degraded + ' degraded' });
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
      const dns = (h.dns && h.dns !== h.host)
        ? escape(h.dns)
        : '<span class="muted">-</span>';
      return '<tr>'
        + '<td>' + (i + 1) + '</td>'
        + '<td>' + escape(h.host) + '</td>'
        + '<td>' + dns + '</td>'
        + '<td>' + zone + '</td>'
        + '<td>' + fmtBytes(h.bytes) + '</td>'
        + '<td>' + h.packets + '</td>'
        + '<td>' + h.flows + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="7" class="muted">no flows yet - start capture</td></tr>';

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
      let baseline = '<span class="muted">learning…</span>';
      if (t.has_baseline) {
        const d = t.baseline_descr || '';
        const cls = d.indexOf('▲') >= 0 ? 'loss-warn' : d.indexOf('▼') >= 0 ? 'loss-ok' : '';
        const band = 'normal band p50 ' + Math.round(t.baseline_p50_ms) + 'ms · p95 '
          + Math.round(t.baseline_p95_ms) + 'ms (n=' + t.baseline_samples + ')';
        baseline = '<span class="' + cls + '" title="' + escape(band) + '">' + escape(d) + '</span>';
      }
      return '<tr>'
        + '<td>' + escape(t.target) + '</td>'
        + '<td>' + fmtUs(t.last_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.avg_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.p50_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.p95_rtt_us) + '</td>'
        + '<td>' + fmtUs(t.p99_rtt_us) + '</td>'
        + '<td class="' + lossClass + '">' + t.loss_pct.toFixed(1) + '%</td>'
        + '<td>' + t.jitter_ms.toFixed(1) + 'ms</td>'
        + '<td>' + baseline + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="9" class="muted">…awaiting first probe</td></tr>';
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
    // Tokenised AND match: every whitespace-separated term must appear
    // somewhere in the flow row. Lets the Sankey click-to-filter set
    // multiple constraints at once (e.g. clicking the link
    // "firefox → wg0" sets the filter to "firefox wg0").
    const raw = (val('flow-filter') || '').toLowerCase().trim();
    const tokens = raw ? raw.split(/\s+/) : [];
    const lines = (rows || []).filter(f => {
      if (!tokens.length) return true;
      const hay = [f.proto, f.iface, f.process, f.a, f.b, f.dns, f.service]
        .map(x => String(x || '').toLowerCase()).join(' ');
      return tokens.every(t => hay.includes(t));
    });
    syncSankeyFilterPill(raw);
    document.getElementById('flows-body').innerHTML = lines.map(f =>
      '<tr>'
      + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
      + '<td>' + escape(f.iface) + '</td>'
      + '<td>' + escape(f.process || '-') + '</td>'
      + '<td>' + escape(f.a) + ipBadge(f.a_label) + '</td>'
      + '<td>' + escape(f.b) + ipBadge(f.b_label) + '</td>'
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
      + '<td>' + escape(f.a) + ipBadge(f.a_label) + '</td>'
      + '<td>' + escape(f.b) + ipBadge(f.b_label) + '</td>'
      + '<td>' + escape(f.service || '-') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="8" class="muted">…awaiting flows</td></tr>';
  }

  // Process -> Iface -> Service -> Host Sankey for the Flows tab. Aggregates
  // the live flow snapshot into a 4-column flow graph weighted by bytes or
  // packets. The Iface column makes tunnel traffic legible: a flow on wg0
  // is visually separated from the same {process, service} pair captured on
  // wlan0/eth0, so the encrypted underlay and decrypted inner traffic don't
  // pile into one bar. Each column is capped to top-N by weight; the
  // remainder rolls into "(other)" so the diagram stays legible under load.
  function renderFlowsSankey(rows) {
    const host = document.getElementById('flows-sankey');
    if (!host) return;
    if (typeof d3 === 'undefined' || !d3.sankey) {
      host.innerHTML = '<div class="sankey-empty">loading sankey library…</div>';
      return;
    }
    const metric = (document.getElementById('sankey-metric') || {}).value || 'bytes';
    const topN = parseInt((document.getElementById('sankey-topn') || {}).value, 10) || 12;
    const weightOf = f => metric === 'packets' ? (f.packets || 0) : (f.bytes || 0);
    const fmtWeight = v => metric === 'packets' ? (v.toLocaleString() + ' pkt') : fmtBytes(v);

    const data = (rows || []).filter(f => weightOf(f) > 0);
    if (!data.length) {
      host.innerHTML = '<div class="sankey-empty">no flows yet - start capture in this tab</div>';
      return;
    }

    // Tag node names with a column prefix so the same string in two columns
    // (e.g. an IP that's also a "service" label) can't collapse into one node.
    const TAG = { P: 'P:', I: 'I:', S: 'S:', H: 'H:' };
    const strip = n => n.slice(2);
    // Show the dst host with port for raw-IP flows so users can tell
    // 192.168.1.1:53 (DNS) apart from 192.168.1.1:443 (HTTPS) when there's
    // no DNS name available.
    const hostOf = f => f.dns || f.b || f.a || '?';
    const svcOf  = f => f.service || (f.proto ? f.proto.toUpperCase() : 'proto');
    const procOf = f => f.process || '(unknown)';
    const ifaceOf = f => f.iface || '(no iface)';

    // First pass: total weight per node so we can pick the top-N per column.
    const total = { P: new Map(), I: new Map(), S: new Map(), H: new Map() };
    const bump = (m, k, v) => m.set(k, (m.get(k) || 0) + v);
    data.forEach(f => {
      const v = weightOf(f);
      bump(total.P, procOf(f),  v);
      bump(total.I, ifaceOf(f), v);
      bump(total.S, svcOf(f),   v);
      bump(total.H, hostOf(f),  v);
    });
    const keep = col => {
      const sorted = [...total[col].entries()].sort((a, b) => b[1] - a[1]);
      return new Set(sorted.slice(0, topN).map(e => e[0]));
    };
    const keepP = keep('P'), keepI = keep('I'), keepS = keep('S'), keepH = keep('H');
    const project = (name, kept) => kept.has(name) ? name : '(other)';

    // Second pass: build links proc->iface->svc->host, rolling non-top into (other).
    const links = new Map();
    const addLink = (s, t, v) => {
      const k = s + '||' + t;
      const ex = links.get(k);
      if (ex) ex.value += v; else links.set(k, { source: s, target: t, value: v });
    };
    data.forEach(f => {
      const v = weightOf(f);
      const p = TAG.P + project(procOf(f),  keepP);
      const i = TAG.I + project(ifaceOf(f), keepI);
      const s = TAG.S + project(svcOf(f),   keepS);
      const h = TAG.H + project(hostOf(f),  keepH);
      addLink(p, i, v);
      addLink(i, s, v);
      addLink(s, h, v);
    });

    const names = new Set();
    links.forEach(l => { names.add(l.source); names.add(l.target); });
    const nodes = [...names].map(name => ({ name }));
    const idx = new Map(nodes.map((n, i) => [n.name, i]));
    const linkArr = [...links.values()].map(l => ({
      source: idx.get(l.source), target: idx.get(l.target), value: l.value,
    }));

    const width  = host.clientWidth || 900;
    const height = Math.max(420, Math.min(720, nodes.length * 18));

    const layout = d3.sankey()
      .nodeWidth(14)
      .nodePadding(10)
      .nodeAlign(d3.sankeyJustify)
      .extent([[1, 6], [width - 1, height - 6]]);
    const graph = layout({
      nodes: nodes.map(d => Object.assign({}, d)),
      links: linkArr.map(d => Object.assign({}, d)),
    });

    const color = name => {
      if (name.startsWith(TAG.P)) return '#58a6ff'; // process – blue
      if (name.startsWith(TAG.I)) return '#f0883e'; // iface – orange
      if (name.startsWith(TAG.S)) return '#a371f7'; // service – purple
      return '#3fb950';                              // host – green
    };
    const columnLabel = tag => {
      if (tag === TAG.P) return 'Process';
      if (tag === TAG.I) return 'Interface';
      if (tag === TAG.S) return 'Service';
      return 'Host';
    };

    // Per-node flow count (rows touching this node) - useful in the tip
    // to tell "one big flow" apart from "many small flows".
    const nodeFlows = { P: new Map(), I: new Map(), S: new Map(), H: new Map() };
    const bumpFlow = (m, k) => m.set(k, (m.get(k) || 0) + 1);
    data.forEach(f => {
      bumpFlow(nodeFlows.P, project(procOf(f),  keepP));
      bumpFlow(nodeFlows.I, project(ifaceOf(f), keepI));
      bumpFlow(nodeFlows.S, project(svcOf(f),   keepS));
      bumpFlow(nodeFlows.H, project(hostOf(f),  keepH));
    });
    // Grand total per column - used for percent-of-traffic in tips.
    const colTotal = { P: 0, I: 0, S: 0, H: 0 };
    data.forEach(f => {
      const v = weightOf(f);
      colTotal.P += v; colTotal.I += v; colTotal.S += v; colTotal.H += v;
    });
    const flowsForNode = name => {
      const tag = name.slice(0, 2);
      const stripped = name.slice(2);
      if (tag === TAG.P) return nodeFlows.P.get(stripped) || 0;
      if (tag === TAG.I) return nodeFlows.I.get(stripped) || 0;
      if (tag === TAG.S) return nodeFlows.S.get(stripped) || 0;
      return nodeFlows.H.get(stripped) || 0;
    };
    const pctForNode = (name, value) => {
      const tag = name.slice(0, 2);
      const tot = colTotal[tag === TAG.P ? 'P' : tag === TAG.I ? 'I' : tag === TAG.S ? 'S' : 'H'];
      return tot > 0 ? (100 * value / tot).toFixed(1) + '%' : '–';
    };

    host.innerHTML = '';
    const svg = d3.select(host).append('svg')
      .attr('viewBox', '0 0 ' + width + ' ' + height)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    // --- tooltip + click-to-filter wiring --------------------------------
    const tip = document.getElementById('sankey-tip');
    const filterInput = document.getElementById('flow-filter');
    const showTip = (html, evt) => {
      if (!tip) return;
      tip.innerHTML = html;
      tip.style.display = 'block';
      tip.setAttribute('aria-hidden', 'false');
      moveTip(evt);
    };
    const moveTip = evt => {
      if (!tip) return;
      const pad = 14;
      const w = tip.offsetWidth, h = tip.offsetHeight;
      let x = evt.clientX + pad, y = evt.clientY + pad;
      if (x + w > window.innerWidth)  x = evt.clientX - w - pad;
      if (y + h > window.innerHeight) y = evt.clientY - h - pad;
      tip.style.left = Math.max(4, x) + 'px';
      tip.style.top  = Math.max(4, y) + 'px';
    };
    const hideTip = () => {
      if (!tip) return;
      tip.style.display = 'none';
      tip.setAttribute('aria-hidden', 'true');
    };
    const applyFilter = (terms) => {
      if (!filterInput) return;
      const next = terms.filter(Boolean).join(' ').trim();
      const cur  = (filterInput.value || '').trim();
      // Toggle off on a second click of the same target.
      filterInput.value = (cur === next) ? '' : next;
      filterInput.dispatchEvent(new Event('input', { bubbles: true }));
    };

    // --- links -----------------------------------------------------------
    svg.append('g').attr('class', 'sankey-links')
      .selectAll('path')
      .data(graph.links)
      .join('path')
        .attr('class', 'sankey-link')
        .attr('d', d3.sankeyLinkHorizontal())
        .attr('stroke', d => color(d.source.name))
        .attr('stroke-opacity', 0.35)
        .attr('stroke-width', d => Math.max(1, d.width))
        .on('mouseover', (evt, d) => {
          const sName = strip(d.source.name), tName = strip(d.target.name);
          const sCol  = columnLabel(d.source.name.slice(0, 2));
          const tCol  = columnLabel(d.target.name.slice(0, 2));
          const html =
            '<div class="tip-row"><span class="tip-muted">' + escape(sCol) + ' → ' + escape(tCol) + '</span></div>' +
            '<div><b>' + escape(sName) + '</b> → <b>' + escape(tName) + '</b></div>' +
            '<div class="tip-row"><span class="tip-muted">' + (metric === 'packets' ? 'packets' : 'bytes') + '</span>' +
              '<span>' + escape(fmtWeight(d.value)) + '</span></div>' +
            '<div class="tip-hint">click to filter flows table</div>';
          showTip(html, evt);
        })
        .on('mousemove', moveTip)
        .on('mouseout', hideTip)
        .on('click', (evt, d) => {
          applyFilter([strip(d.source.name), strip(d.target.name)]);
          hideTip();
        });

    // --- nodes -----------------------------------------------------------
    const node = svg.append('g').attr('class', 'sankey-nodes')
      .selectAll('g').data(graph.nodes).join('g').attr('class', 'sankey-node');

    node.append('rect')
      .attr('x', d => d.x0).attr('y', d => d.y0)
      .attr('width', d => Math.max(1, d.x1 - d.x0))
      .attr('height', d => Math.max(1, d.y1 - d.y0))
      .attr('fill', d => color(d.name))
      .attr('fill-opacity', 0.85)
      .on('mouseover', (evt, d) => {
        const col = columnLabel(d.name.slice(0, 2));
        const name = strip(d.name);
        const w = d.value || 0;
        const html =
          '<div class="tip-row"><span class="tip-muted">' + escape(col) + '</span>' +
            '<span>' + escape(pctForNode(d.name, w)) + '</span></div>' +
          '<div><b>' + escape(name) + '</b></div>' +
          '<div class="tip-row"><span class="tip-muted">' + (metric === 'packets' ? 'packets' : 'bytes') + '</span>' +
            '<span>' + escape(fmtWeight(w)) + '</span></div>' +
          '<div class="tip-row"><span class="tip-muted">flows</span>' +
            '<span>' + flowsForNode(d.name) + '</span></div>' +
          '<div class="tip-hint">click to filter - click again to clear</div>';
        showTip(html, evt);
      })
      .on('mousemove', moveTip)
      .on('mouseout', hideTip)
      .on('click', (evt, d) => {
        const name = strip(d.name);
        // "(other)" and "(unknown)" buckets aren't useful filter terms.
        if (name === '(other)' || name === '(unknown)' || name === '(no iface)') {
          hideTip();
          return;
        }
        applyFilter([name]);
        hideTip();
      });

    node.append('text')
      .attr('class', 'sankey-label')
      .attr('x', d => d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6)
      .attr('y', d => (d.y1 + d.y0) / 2)
      .attr('dy', '0.35em')
      .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
      .text(d => {
        const label = strip(d.name);
        // Trim very long DNS names so they don't blow past the SVG edge.
        return label.length > 36 ? label.slice(0, 34) + '…' : label;
      });
  }

  // syncSankeyFilterPill mirrors the current #flow-filter value into the
  // dismissable pill next to the Sankey title. Called from renderFlows so
  // it stays in sync whether the filter was set by typing, by clicking a
  // Sankey node/link, or by clicking the pill itself to clear.
  function syncSankeyFilterPill(raw) {
    const pill = document.getElementById('sankey-filter-pill');
    const text = document.getElementById('sankey-filter-pill-text');
    if (!pill || !text) return;
    const v = (raw || '').trim();
    if (!v) {
      pill.classList.remove('is-active');
      return;
    }
    text.textContent = 'filter: ' + v;
    pill.classList.add('is-active');
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
        + '<td><b>' + ip + '</b>' + ipBadge(d.ip_label) + '</td>'
        + '<td>' + escape(d.hostname || '-') + '</td>'
        + '<td>' + vendorCell(d) + '</td>'
        + '<td>' + ports + '</td>'
        + '<td>' + connectBtns + '</td>'
        + '<td>'
        +   '<button class="btn btn-small" data-action="device-scan" data-ip="' + ip + '">Scan</button>'
        + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">no devices yet</td></tr>';
  }

  // vendorCell renders the device vendor, or - when there's no vendor and the
  // MAC is randomized/private - a muted "randomized" tag explaining why no OUI
  // could be resolved.
  function vendorCell(d) {
    if (d.vendor) return escape(d.vendor);
    if (d.mac_type === 'randomized') return '<span class="muted">randomized</span>';
    return '-';
  }

  // neighStateClass maps a NUD state to a status-pill colour. FAILED /
  // INCOMPLETE are the operationally bad states (gateway loss precursor).
  function neighStateClass(state) {
    if (state === 'REACHABLE' || state === 'PERMANENT' || state === 'NOARP') return 'on';
    if (state === 'FAILED' || state === 'INCOMPLETE') return 'off';
    return 'warn';
  }

  function renderNeighbours(rows, conflicts) {
    // Conflict banner: duplicate IPs are a hard local-network fault.
    const banner = document.getElementById('neigh-conflicts');
    if (banner) {
      if ((conflicts || []).length) {
        banner.style.display = '';
        banner.innerHTML = (conflicts || []).map(c =>
          '<span class="status-pill off">DUPLICATE ' + escape(c.ip) + '</span> answered by '
          + escape((c.macs || []).join(', ')) + ' on ' + escape((c.devs || []).join(', '))
        ).join('<br>');
      } else {
        banner.style.display = 'none';
        banner.innerHTML = '';
      }
    }
    const body = document.getElementById('neigh-body');
    if (!body) return;
    body.innerHTML = (rows || []).map(n => {
      const conflictBadge = n.conflict ? ' <span class="status-pill off">conflict</span>' : '';
      const routerBadge = n.router ? ' <span class="status-pill">router</span>' : '';
      const rowCls = n.conflict ? ' class="row-danger"' : '';
      return '<tr' + rowCls + '>'
        + '<td><b>' + escape(n.ip) + '</b>' + conflictBadge + routerBadge + '</td>'
        + '<td><code>' + escape(n.mac || '-') + '</code></td>'
        + '<td>' + escape(n.dev || '-') + '</td>'
        + '<td>' + escape(n.family) + '</td>'
        + '<td><span class="status-pill ' + neighStateClass(n.state) + '">' + escape(n.state) + '</span></td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="5" class="muted">no neighbours - needs CAP_NET_ADMIN, or none learned yet</td></tr>';
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
        lines.push('<div class="muted">radio is up but not joined to an AP - no SSID / channel / bitrate data</div>');
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

  // wifiQualityScore mirrors the Go grade's scoreWiFi: blend RSSI with SNR and
  // the TX-failure rate so a strong-signal-but-failing link is scored honestly.
  // Returns 0..100, or null when the radio is unassociated / has no signal.
  function wifiQualityScore(w) {
    if (!w.associated || !w.signal_dbm) return null;
    const clamp = v => Math.max(0, Math.min(100, Math.round(v)));
    const comps = [clamp((w.signal_dbm + 90) / 30 * 100)];        // RSSI
    if (w.noise_dbm) comps.push(clamp((w.signal_dbm - w.noise_dbm - 10) / 20 * 100)); // SNR
    const tot = (w.tx_packets || 0) + (w.tx_failed || 0);
    if (tot >= 100) {                                             // TX-failure rate vs 5%
      const failPct = (w.tx_failed || 0) / tot * 100;
      const ratio = failPct / 5;
      comps.push(ratio <= 1 ? clamp(100 - 50 * ratio) : (ratio <= 2 ? clamp(50 - 50 * (ratio - 1)) : 0));
    }
    return Math.round(comps.reduce((a, b) => a + b, 0) / comps.length);
  }

  function qualityClass(score) {
    if (score >= 85) return 'ok';
    if (score >= 60) return 'warn';
    return 'bad';
  }

  // renderWiFiDetail draws the dedicated WiFi tab: a richer per-radio card with
  // a computed quality grade badge on top of the full counter set.
  function renderWiFiDetail(rows) {
    const host = document.getElementById('wifi-detail');
    if (!host) return;
    if (!rows || rows.length === 0) {
      host.innerHTML = '<div class="muted">no wireless interfaces detected (no NICs under /sys/class/net/*/wireless). nl80211 needs CAP_NET_ADMIN - run with sudo or grant <code>setcap cap_net_admin+ep</code>.</div>';
      return;
    }
    host.innerHTML = rows.map(w => {
      const assoc = w.associated;
      const headerClass = assoc ? 'wifi-card' : 'wifi-card idle';
      const q = wifiQualityScore(w);
      let badge = '';
      if (q !== null) {
        const cls = qualityClass(q);
        badge = '<span class="wifi-q ' + cls + '">' + q + '/100</span>';
      }
      const sigClass = !assoc || !w.signal_dbm ? 'muted'
        : (w.signal_dbm < -85 ? 'err' : (w.signal_dbm < -75 ? 'warn' : 'ok'));
      const lines = [];
      lines.push('<div class="wifi-head"><b>' + escape(w.iface) + '</b> '
        + (assoc ? '<span class="status-pill on">associated</span>'
                 : '<span class="status-pill warn">unassociated</span>')
        + ' ' + badge
        + ' <span class="muted">' + escape(w.hw_addr || '-') + '</span>'
        + (w.source ? ' <span class="muted">(' + escape(w.source) + ')</span>' : '')
        + '</div>');
      if (!assoc) {
        lines.push('<div class="muted">radio is up but not joined to an AP - no SSID / channel / bitrate data</div>');
        return '<div class="' + headerClass + '">' + lines.join('') + '</div>';
      }
      lines.push('<dl class="wifi-grid">');
      lines.push('<dt>SSID</dt><dd>' + escape(w.ssid || '(unknown)') + '</dd>');
      lines.push('<dt>BSSID</dt><dd class="mono">' + escape(w.bssid || '-') + '</dd>');
      if (w.frequency_mhz > 0) {
        const ch = w.channel_width_mhz > 0 ? (w.channel + ' (' + w.channel_width_mhz + ' MHz wide)') : String(w.channel);
        lines.push('<dt>Channel</dt><dd>' + escape(ch) + ' · ' + w.frequency_mhz + ' MHz · ' + escape(w.band) + '</dd>');
      }
      const sigParts = ['<span class="' + sigClass + '">' + Math.round(w.signal_dbm) + ' dBm</span>'];
      if (w.signal_avg_dbm && w.signal_avg_dbm !== w.signal_dbm) sigParts.push('avg ' + Math.round(w.signal_avg_dbm));
      if (w.noise_dbm) sigParts.push('noise ' + Math.round(w.noise_dbm) + ' · SNR ' + Math.round(w.signal_dbm - w.noise_dbm) + ' dB');
      lines.push('<dt>Signal</dt><dd>' + sigParts.join(' · ') + '</dd>');
      if (w.tx_bitrate_mbps > 0 || w.rx_bitrate_mbps > 0) {
        lines.push('<dt>Bitrate</dt><dd>tx ' + w.tx_bitrate_mbps.toFixed(1) + ' Mbit/s · rx ' + w.rx_bitrate_mbps.toFixed(1) + ' Mbit/s</dd>');
      }
      if (w.tx_power_dbm > 0) lines.push('<dt>TX power</dt><dd>' + w.tx_power_dbm.toFixed(1) + ' dBm</dd>');
      if (w.link_quality > 0) {
        const max = w.link_quality_max || 70;
        lines.push('<dt>Quality</dt><dd>' + w.link_quality + '/' + max + ' (' + Math.round(w.link_quality / max * 100) + '%)</dd>');
      }
      const failHi = (w.tx_failed || 0) > 0 || (w.beacon_loss || 0) > 0;
      lines.push('<dt>Counters</dt><dd' + (failHi ? ' class="warn"' : '') + '>retries ' + (w.retries || 0)
        + ' · tx-failed ' + (w.tx_failed || 0) + ' · beacon-loss ' + (w.beacon_loss || 0) + '</dd>');
      if ((w.rx_bytes || 0) + (w.tx_bytes || 0) > 0) {
        lines.push('<dt>Station</dt><dd>rx ' + fmtBytes(w.rx_bytes) + ' (' + w.rx_packets + ' pkts) · tx ' + fmtBytes(w.tx_bytes) + ' (' + w.tx_packets + ' pkts)</dd>');
      }
      if (w.connected_for) lines.push('<dt>Up since</dt><dd>' + escape(w.connected_for) + ' ago</dd>');
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

  // renderWatcher mirrors the TUI's live/polled badge: the Interfaces and
  // Routes tables update the instant the kernel multicasts a change when the
  // RTNETLINK watcher is attached ("live"); if the subscription was refused it
  // falls back to the slow reconcile timer ("polled").
  function renderWatcher(w) {
    w = w || {};
    let html = '';
    if (w.mode === 'live') {
      const churn = (w.flap_rate || w.route_churn)
        ? ' · ' + Math.round(w.flap_rate || 0) + ' flaps/min, ' + Math.round(w.route_churn || 0) + ' route chg/min'
        : '';
      html = '<span class="status-pill on">● live</span>'
        + '<span class="muted"> push (sub-second)' + churn + '</span>';
    } else if (w.mode === 'polled') {
      html = '<span class="status-pill warn">● polled</span>'
        + '<span class="muted"> ' + escape(w.detail || 'netlink subscribe unavailable') + '</span>';
    }
    ['ifaces-watcher', 'routes-watcher'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = html;
    });
  }

  function renderFirewall(rules, system, ruleCounters) {
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

    // Per-rule counters. Rules arrive top-sorted per chain (highest-hit
    // DROP/REJECT first). A rule without a counter renders pkts/bytes as a
    // dash and the reset button is disabled with a legacy-rule hint.
    document.getElementById('fw-rules-counter-body').innerHTML =
      (ruleCounters || []).map(r => {
        const pkts = r.has_counter ? r.packets : '-';
        const bytes = r.has_counter ? fmtBytes(r.bytes) : '-';
        const chain = escape(r.family + '/' + r.table + '/' + r.chain);
        const verdictCls = r.blocking ? ' class="status-pill off"' : '';
        const resetBtn = r.has_counter
          ? '<button class="btn btn-small" data-action="fw-reset"'
            + ' data-family="' + escape(r.family) + '"'
            + ' data-table="' + escape(r.table) + '"'
            + ' data-chain="' + escape(r.chain) + '"'
            + ' data-handle="' + r.handle + '">reset</button>'
          : '<span class="muted" title="legacy rule - recreate via Testudo to enable counting">no counter</span>';
        return '<tr>'
          + '<td>' + chain + '</td>'
          + '<td>' + r.handle + '</td>'
          + '<td><code>' + escape(r.match || 'any') + '</code></td>'
          + '<td><span' + verdictCls + '>' + escape(r.verdict || '-') + '</span></td>'
          + '<td>' + pkts + '</td>'
          + '<td>' + bytes + '</td>'
          + '<td>' + resetBtn + '</td>'
          + '</tr>';
      }).join('') || '<tr><td colspan="7" class="muted">no kernel rules visible</td></tr>';
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

  function renderConntrack(ct, allowWrite) {
    ct = ct || {};
    // Utilisation gauge: live entries / nf_conntrack_max.
    const gauge = document.getElementById('conntrack-util');
    if (gauge) {
      if (ct.max > 0) {
        const pct = Math.min(100, Math.round((ct.count / ct.max) * 100));
        const cls = pct >= 95 ? 'off' : pct >= 80 ? 'warn' : 'on';
        gauge.innerHTML = '<span class="status-pill ' + cls + '">' + pct + '% full</span> '
          + '<span class="muted">' + ct.count + ' / ' + ct.max + ' entries</span>';
      } else {
        gauge.innerHTML = '<span class="muted">conntrack not loaded</span>';
      }
    }
    const body = document.getElementById('conntrack-body');
    if (!body) return;
    body.innerHTML = (ct.flows || []).map(f => {
      const orig = escape(f.orig_src) + ':' + f.orig_sport + ' → ' + escape(f.orig_dst) + ':' + f.orig_dport;
      const reply = f.natted
        ? '<span class="status-pill warn">NAT</span> ' + escape(f.reply_src) + ' → ' + escape(f.reply_dst)
        : '<span class="muted">-</span>';
      const dataFlow = JSON.stringify(f).replace(/"/g, '&quot;');
      const flushBtn = allowWrite
        ? '<button class="btn btn-small btn-danger" data-action="ct-flush" data-flow="' + dataFlow + '">flush</button>'
        : '<button class="btn btn-small" disabled title="enable netops writes in Settings to flush">flush</button>';
      return '<tr>'
        + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
        + '<td>' + orig + '</td>'
        + '<td>' + reply + '</td>'
        + '<td><span class="status-pill">' + escape(f.state) + '</span></td>'
        + '<td>' + fmtBytes(f.bytes) + '</td>'
        + '<td>' + f.timeout_sec + 's</td>'
        + '<td>' + flushBtn + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="7" class="muted">no live conntrack flows</td></tr>';
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
    document.getElementById('s-expdown').value = t.expected_down_mbps || 0;
    document.getElementById('s-expup').value = t.expected_up_mbps || 0;
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
      const upTop = document.getElementById('uptime-top');
      if (upTop) upTop.textContent = snap.uptime || '-';
      // Pulse the topbar live indicator on every successful poll so the
      // operator can see the snapshot loop is actually breathing.
      const dot = document.getElementById('live-dot');
      if (dot) { dot.classList.remove('pulse'); void dot.offsetWidth; dot.classList.add('pulse'); }
      renderGrade(snap.grade || {});
      renderKpis(snap);
      renderBandwidth(snap.bandwidth || []);
      renderTalkers(snap.top_hosts, snap.top_processes, snap.top_services);
      renderSparks('icmp-sparks', snap.latency_series || {}, '#58a6ff');
      renderSparks('dns-sparks',  snap.dns_series || {}, '#a371f7');
      renderTargets(snap.targets);
      renderDNS(snap.dns);
      renderFlows(snap.flows);
      renderFlowsSankey(snap.flows);
      renderDevices(snap.devices);
      renderNeighbours(snap.neighbours, snap.ip_conflicts);
      renderIfaces(snap.ifaces, snap.wifi);
      renderWiFi(snap.wifi);
      renderWiFiDetail(snap.wifi);
      renderRoutes(snap.routes);
      renderWatcher(snap.watcher);
      renderFirewall(snap.filter_rules, snap.firewall, snap.firewall_rules);
      renderNAT(snap.nat);
      renderConntrack(snap.conntrack, snap.thresholds && snap.thresholds.allow_netops_write);
      renderTCPDump(snap.tcpdump);
      renderAlerts(snap.anomalies);
      renderCapture(snap.capture || { running: false, ifaces: [] });
      renderIPFIX(snap.ipfix);
      renderHealth(snap.subsystems, snap.audit, snap.privsep);
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

  // Sankey filter pill: clears the flow-filter and re-renders. Same handler
  // for click and keyboard activation (Enter / Space) so the pill is usable
  // without a mouse.
  const sankeyPill = document.getElementById('sankey-filter-pill');
  if (sankeyPill) {
    const clearFlowFilter = () => {
      const inp = document.getElementById('flow-filter');
      if (!inp) return;
      inp.value = '';
      inp.dispatchEvent(new Event('input', { bubbles: true }));
    };
    sankeyPill.addEventListener('click', clearFlowFilter);
    sankeyPill.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clearFlowFilter(); }
    });
  }
  // Sankey controls re-render immediately; aggregation runs on the most-recent
  // flow snapshot, so we don't need to refetch.
  ['sankey-metric', 'sankey-topn'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => refresh());
  });

  document.getElementById('logout').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
  });

  refresh();
  setInterval(refresh, 2000);
})();
