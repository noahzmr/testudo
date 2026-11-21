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
    if (target === 'access') loadAccess();
    // Hidden panes are not rendered by the poll; paint this one now from
    // the last snapshot instead of waiting up to 2 s.
    renderActive();
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
  // Every request times out: a hung connection must not wedge the refresh
  // loop (it skips while a poll is in flight) and freeze the console.
  const API_TIMEOUT_MS = 15000;
  async function api(path, method, body) {
    const init = { method: method || 'GET', signal: AbortSignal.timeout(API_TIMEOUT_MS) };
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
      case 'fw-del': {
        if (!confirm('Delete rule ' + btn.dataset.text + ' ?')) return;
        await post('/api/firewall/del', { id: btn.dataset.id });
        showToast('rule deleted');
        break;
      }

      // ---- privileged access ----
      case 'pam-request':
        await post('/api/pam/request', {
          resource_id: val('pam-res'), ttl_sec: parseInt(val('pam-ttl') || '60', 10) * 60,
          justification: val('pam-just'), ticket: val('pam-ticket'),
        });
        showToast('access requested');
        clearInputs(['pam-just', 'pam-ticket']);
        await loadAccess();
        break;
      case 'pam-breakglass': {
        if (!confirm('BREAK GLASS: immediate access without policy or approval, loudly logged. Continue?')) return;
        await post('/api/pam/breakglass', {
          resource_id: val('pam-res'), ttl_sec: parseInt(val('pam-ttl') || '60', 10) * 60,
          justification: val('pam-just'),
        });
        showToast('break-glass access active');
        clearInputs(['pam-just']);
        await loadAccess();
        break;
      }
      case 'pam-approve':
        await post('/api/pam/approve', { grant_id: btn.dataset.id });
        showToast('grant approved and activated');
        await loadAccess();
        break;
      case 'pam-deny': {
        const reason = prompt('Reason for denying ' + btn.dataset.id + ':');
        if (reason === null) return;
        await post('/api/pam/deny', { grant_id: btn.dataset.id, reason });
        showToast('grant denied');
        await loadAccess();
        break;
      }
      case 'pam-revoke': {
        const reason = prompt('Reason for revoking ' + btn.dataset.id + ' (live connections will be cut):');
        if (reason === null) return;
        await post('/api/pam/revoke', { grant_id: btn.dataset.id, reason });
        showToast('grant revoked');
        await loadAccess();
        break;
      }
      case 'pam-ssh-cert': {
        const pub = prompt('Paste your SSH public key (contents of ~/.ssh/id_ed25519.pub). It is signed for this grant only:');
        if (!pub) return;
        const r = await post('/api/pam/ssh/cert', { grant_id: btn.dataset.id, public_key: pub });
        if (r && r.certificate) {
          const box = document.getElementById('pam-cert-result');
          if (box) {
            box.hidden = false;
            document.getElementById('pam-cert-text').textContent = r.certificate;
            document.getElementById('pam-cert-hint').textContent = r.hint || '';
            box.scrollIntoView({ block: 'nearest' });
          }
          showToast('certificate issued for ' + (r.principals || []).join(','));
        }
        break;
      }
      // ---- identity: my account + user management (admin) ----
      case 'me-passwd':
        await post('/api/me/passwd', { current: val('me-cur'), new: val('me-new') });
        showToast('password changed');
        clearInputs(['me-cur', 'me-new']);
        break;
      case 'me-totp-enroll': {
        const pw = prompt('Confirm your password to enroll an authenticator app:');
        if (!pw) return;
        const r = await post('/api/me/totp/enroll', { password: pw });
        showTOTP(r && r.otpauth);
        loadMe();
        break;
      }
      case 'me-totp-disable': {
        const pw = prompt('Confirm your password to disable MFA:');
        if (!pw) return;
        await post('/api/me/totp/disable', { password: pw });
        showToast('MFA disabled');
        hideTOTP();
        loadMe();
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
      case 'nat-del':
        if (!confirm('Delete forward ' + btn.dataset.proto + '/' + btn.dataset.port + '?')) return;
        await post('/api/nat/del', { id: btn.dataset.id });
        showToast('forward removed');
        break;
      case 'wg-add': {
        const serverKeygen = val('wg-keygen') !== 'client';
        const pub = val('wg-pubkey');
        if (!serverKeygen && !pub) { showToast('client keygen needs the peer public key', true); return; }
        const res = await post('/api/wireguard/peer', {
          name: val('wg-name'),
          preset: val('wg-preset'),
          server_keygen: serverKeygen,
          public_key: pub,
          fixed_ip: val('wg-fixedip'),
        });
        showToast('peer provisioned (' + (res && res.assigned_ip || '') + ')');
        clearInputs(['wg-name', 'wg-pubkey', 'wg-fixedip']);
        // Server-side keygen returns the client config exactly once. Show it in
        // a modal and render the QR client-side; the server never stored it.
        if (res && res.client_config) showWireGuardConfig(res.assigned_ip, res.client_config);
        break;
      }
      case 'wg-edit':
        openWGEdit(btn.dataset.pubkey, btn.dataset.short, btn.dataset.endpoint, btn.dataset.allowed, parseInt(btn.dataset.keepalive || '0', 10));
        return; // modal handles the save; no refresh needed yet
      case 'wg-edit-cancel':
        document.getElementById('wg-edit-modal').hidden = true;
        return;
      case 'wg-edit-save': {
        const pub = document.getElementById('wg-edit-modal').dataset.pubkey;
        const kaRaw = val('wg-edit-keepalive');
        const body = {
          public_key: pub,
          endpoint: val('wg-edit-endpoint'),
          allowed_ips: wgCombo.getValues(),
          preset: val('wg-edit-preset'),
        };
        // Blank = leave unchanged; a number (incl. 0 = off) is sent through.
        if (kaRaw !== '') body.keepalive_sec = parseInt(kaRaw, 10);
        await post('/api/wireguard/peer/update', body);
        document.getElementById('wg-edit-modal').hidden = true;
        showToast('peer updated');
        break;
      }
      case 'wg-netplan-render': {
        const res = await post('/api/wireguard/netplan/render', { private_key: val('wg-if-key') });
        const pre = document.getElementById('wg-netplan-preview');
        pre.textContent = (res && res.netplan) || '';
        pre.hidden = false;
        showToast('netplan rendered (preview)');
        break;
      }
      case 'wg-netplan-write': {
        if (!confirm('Write the netplan file for the wg interface? Apply afterwards with `sudo netplan apply`.')) return;
        const res = await post('/api/wireguard/netplan/write', { private_key: val('wg-if-key') });
        // Wipe the private key field after a successful write.
        const k = document.getElementById('wg-if-key'); if (k) k.value = '';
        showToast('wrote ' + ((res && res.path) || 'netplan') + ' - run netplan apply below');
        break;
      }
      case 'wg-np-load':
        await loadNetplanFiles();
        showToast('netplan files loaded');
        break;
      case 'wg-np-save': {
        const path = document.getElementById('wg-np-select').value;
        if (!path) { showToast('no netplan file selected', true); return; }
        await post('/api/wireguard/netplan/save', {
          path: path,
          content: document.getElementById('wg-np-editor').value,
        });
        showToast('saved ' + path);
        break;
      }
      case 'wg-np-apply':
        if (!confirm('Run `netplan apply`? This reloads the system network config and can briefly interrupt connectivity.')) return;
        await post('/api/wireguard/netplan/apply', {});
        showToast('netplan apply ok');
        break;
      case 'wg-np-save-apply': {
        const path = document.getElementById('wg-np-select').value;
        if (!path) { showToast('no netplan file selected', true); return; }
        if (!confirm('Save ' + path + ' and run netplan apply?\nBacked up first; auto-rolls back if it fails validation or apply.')) return;
        await post('/api/wireguard/netplan/save-apply', {
          path: path,
          content: document.getElementById('wg-np-editor').value,
        });
        showToast('saved & applied ' + path);
        break;
      }
      case 'wg-deprovision':
        if (!confirm('Deprovision peer ' + btn.dataset.short + '? Removes peer, route, firewall rules, and frees the IP.')) return;
        await post('/api/wireguard/peer/deprovision', { public_key: btn.dataset.pubkey });
        showToast('peer deprovisioned');
        break;
      case 'wg-iface-create': {
        const dev = val('wg-if-new-dev');
        if (!dev) { showToast('device name required', true); return; }
        const res = await post('/api/wireguard/interface', {
          device: dev,
          address: val('wg-if-new-addr'),
          listen_port: parseInt(val('wg-if-new-port') || '0', 10),
          private_key: val('wg-if-new-key'),
        });
        const k = document.getElementById('wg-if-new-key'); if (k) k.value = '';
        clearInputs(['wg-if-new-dev', 'wg-if-new-addr', 'wg-if-new-port']);
        if (res && res.public_key) {
          showWireGuardConfig(dev + ' public key', 'PublicKey = ' + res.public_key + '\n\n(interface created; private key is stored only in the netplan file)');
        } else {
          showToast('interface ' + dev + ' created');
        }
        break;
      }
      case 'wg-iface-delete':
        if (!confirm('Delete interface ' + btn.dataset.dev + '? Removes its Testudo netplan file and applies. Peers on it are lost.')) return;
        await post('/api/wireguard/interface/delete', { device: btn.dataset.dev });
        showToast('interface ' + btn.dataset.dev + ' deleted');
        break;
      case 'wg-iface-tune':
        if (!confirm('Tune ' + btn.dataset.dev + ' for max performance?\nSets MTU 1420, txqueuelen 1000, and enlarges UDP socket buffers (system-wide).')) return;
        await post('/api/wireguard/interface/tune', { device: btn.dataset.dev, recommended: true });
        showToast(btn.dataset.dev + ' tuned - if errors persist, lower the MTU');
        break;
      case 'wg-iface-mtu': {
        const cur = btn.dataset.mtu && btn.dataset.mtu !== '0' ? btn.dataset.mtu : '1420';
        const mtu = prompt('MTU for ' + btn.dataset.dev + ' (1420 default; try 1380 or 1280 if you see tx/rx errors):', cur);
        if (!mtu) return;
        const n = parseInt(mtu, 10);
        if (!(n >= 576 && n <= 9000)) { showToast('MTU must be 576-9000', true); return; }
        await post('/api/wireguard/interface/tune', { device: btn.dataset.dev, mtu: n });
        showToast(btn.dataset.dev + ' MTU set to ' + n);
        break;
      }
      case 'wg-iface-rename': {
        const name = prompt('Name for ' + btn.dataset.dev + ':', btn.dataset.label || '');
        if (name === null) return;
        await post('/api/wireguard/interface/name', { device: btn.dataset.dev, name: name.trim() });
        showToast('interface name saved');
        break;
      }
      case 'wg-iface-restart':
        if (!confirm('Restart ' + btn.dataset.dev + '? Bounces the link (down/up) - the tunnel drops briefly.')) return;
        await post('/api/wireguard/interface/restart', { device: btn.dataset.dev });
        showToast(btn.dataset.dev + ' restarted');
        break;
      case 'wg-config-copy': {
        const txt = document.getElementById('wg-config-text').textContent || '';
        try { await navigator.clipboard.writeText(txt); showToast('config copied'); }
        catch (_) { showToast('copy failed - select the text manually', true); }
        break;
      }
      case 'wg-config-close':
        hideWireGuardConfig();
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
      guacamole_api_user:   val('s-guac-api-user'),
      guacamole_api_password: val('s-guac-api-pass') || null,
      guacamole_recording_path:  val('s-guac-rec'),
      guacamole_typescript_path: val('s-guac-ts'),
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
    // A negative latency is a "no sample" sentinel from the probe layer
    // (e.g. math.MinInt64), never a measurement.
    if (!us || us < 0) return '-';
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

  // ---- On-demand libraries ----
  // index.html lists each library's vendored files as
  // <meta name="lazy-script" data-lib="…" content="/static/…?v=hash">; they
  // load in order the first time a view needs them, so the console's first
  // paint does not wait for d3 or the QR encoder.
  const libLoads = {};
  function loadLib(name) {
    if (libLoads[name]) return libLoads[name];
    const urls = Array.from(document.querySelectorAll('meta[name="lazy-script"][data-lib="' + name + '"]'))
      .map(m => m.content);
    libLoads[name] = urls.reduce((chain, url) => chain.then(() => new Promise((resolve, reject) => {
      const el = document.createElement('script');
      el.src = url;
      el.onload = resolve;
      el.onerror = () => reject(new Error('failed to load ' + url));
      document.head.appendChild(el);
    })), Promise.resolve());
    libLoads[name].catch(() => { delete libLoads[name]; }); // allow a retry
    return libLoads[name];
  }

  // renderQR draws text as an SVG QR code (error correction M) into el.
  // Used for TOTP enrolment URIs and WireGuard client configs; both contain
  // secrets, so nothing is sent anywhere and no title/alt echoes the text.
  function renderQR(el, text, size) {
    if (!el) return;
    el.innerHTML = '<span class="muted">rendering QR…</span>';
    loadLib('qr').then(() => {
      window.qrcode.stringToBytes = window.qrcode.stringToBytesFuncs['UTF-8'];
      const q = window.qrcode(0, 'M');
      q.addData(text, 'Byte');
      q.make();
      el.innerHTML = q.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
      const svg = el.querySelector('svg');
      if (svg) {
        svg.setAttribute('width', size);
        svg.setAttribute('height', size);
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'QR code');
        svg.classList.add('qr-svg');
      }
    }).catch(() => {
      el.innerHTML = '<span class="muted">QR unavailable - import the text above instead.</span>';
    });
  }

  // ---- Sparklines (inline SVG) ----
  // sparkLines draws one or more series on a shared zero-based scale. With
  // opts.threshold the alert threshold is drawn as a dashed line and included
  // in the scale, so a line's height reads against "when does this alert",
  // not against its own min/max: a calm 5 ms target hugs the floor, a target
  // creeping toward the threshold visibly climbs to it.
  const SPARK_W = 200;
  const SPARK_H = 26;
  function sparkLines(series, opts) {
    opts = opts || {};
    const open = '<svg class="spark-svg" viewBox="0 0 ' + SPARK_W + ' ' + SPARK_H
      + '" preserveAspectRatio="none" aria-hidden="true" focusable="false">';
    const all = [];
    series.forEach(s => (s.values || []).forEach(v => { if (v >= 0) all.push(v); }));
    if (!all.length) {
      return open + '<line x1="0" y1="' + (SPARK_H - 2) + '" x2="' + SPARK_W + '" y2="' + (SPARK_H - 2)
        + '" stroke="#2a313c" vector-effect="non-scaling-stroke"/></svg>';
    }
    const thr = opts.threshold > 0 ? opts.threshold : 0;
    const max = Math.max(Math.max(...all), thr) || 1;
    const y = v => ((SPARK_H - 2) - (Math.max(v, 0) / max) * (SPARK_H - 4)).toFixed(1);
    let out = open;
    if (thr) {
      out += '<line x1="0" x2="' + SPARK_W + '" y1="' + y(thr) + '" y2="' + y(thr)
        + '" stroke="#d29922" stroke-opacity="0.5" stroke-dasharray="3 3" vector-effect="non-scaling-stroke"/>';
    }
    series.forEach(s => {
      const v = (s.values || []).filter(x => x >= 0);
      if (!v.length) return;
      const step = v.length > 1 ? SPARK_W / (v.length - 1) : 0;
      const pts = v.map((x, i) => (i * step).toFixed(1) + ',' + y(x)).join(' ');
      out += '<polyline fill="none" stroke="' + s.color + '" stroke-width="1.5" stroke-linejoin="round"'
        + ' vector-effect="non-scaling-stroke" points="' + pts + '"/>';
    });
    return out + '</svg>';
  }

  // setHTML skips the DOM write when the markup is unchanged, so a 2 s poll
  // that brings no news keeps hover, focus and open tooltips intact.
  function setHTML(el, html) {
    if (!el || el._html === html) return;
    el.innerHTML = html;
    el._html = html;
  }

  // The server classifies targets (metrics.ClassifyTarget) and ships only
  // probe targets with their kind; this fallback mirrors it for an older
  // server that sends neither.
  function targetKind(name) {
    if (/^(wifi|trace|bufferbloat):/.test(name)) return 'internal';
    if (/^https?:\/\//.test(name)) return 'http';
    if (/^(\[[^\]]+\]|[^:]+):\d+$/.test(name)) return 'tcp';
    return 'icmp';
  }
  const KIND_ORDER = { icmp: 0, tcp: 1, http: 2 };
  // Alert threshold per probe kind, in ms. HTTP uses the TTFB comfort level
  // the grade scores against.
  function targetThreshold(kind) {
    if (kind === 'http') return 500;
    return Number(lastThresholds.rtt_ms) || 150;
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
    // render them as an empty hatched track so the operator can see they
    // were excluded from the overall grade instead of contributing a fake 100.
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
    setHTML(bars, rows.map(([label, score]) => {
      let tip = escape(GRADE_HELP[label] || '') + GRADE_SCORING;
      if (label === 'Loss' && g.loss_has_tcp) {
        tip += escape(' - now: ICMP ' + (g.loss_icmp_pct || 0).toFixed(1) + '%, TCP retrans '
          + (g.loss_tcp_pct || 0).toFixed(1) + '%, conn-fail ' + (g.loss_conn_fail_rate || 0).toFixed(1) + '/s.');
      }
      const attrs = ' data-tip="' + tip + '" tabindex="0"';
      if (noData.has(label)) {
        return '<div class="grade-bar is-nodata"' + attrs + '>'
          + '<span>' + escape(label) + '</span>'
          + '<div class="grade-bar-track"></div>'
          + '<span class="grade-bar-value">no data</span>'
          + '</div>';
      }
      const color = score >= 85 ? 'var(--accent)'
                 : score >= 70 ? 'var(--accent-yellow)'
                 : score >= 60 ? 'var(--accent-orange)'
                 :              'var(--accent-red)';
      return '<div class="grade-bar"' + attrs + '>'
        + '<span>' + escape(label) + '</span>'
        + '<div class="grade-bar-track"><div class="grade-bar-fill" style="width:' + (score || 0) + '%;background:' + color + '"></div></div>'
        + '<span class="grade-bar-value">' + (score || 0) + '</span>'
        + '</div>';
    }).join(''));
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
          + '<td>' + escape(e.actor || '-') + '</td>'
          + '<td>' + (e.peer_uid || 0) + '</td>'
          + '<td class="' + (ok ? 'ok' : 'err') + '">' + escape(ok ? 'ok' : e.result) + '</td>'
          + '</tr>';
      }).join('') || '<tr><td colspan="5" class="muted">no privileged mutations recorded</td></tr>';
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

  // One row per interface with rx and tx on a shared scale, busiest first.
  // Interfaces that moved no bytes in the whole window (idle bridges, veths,
  // libvirt) collapse into one line instead of a wall of flat sparklines.
  function renderBandwidth(rows) {
    const el = document.getElementById('bandwidth-list');
    if (!rows || rows.length === 0) {
      setHTML(el, '<div class="muted">…awaiting first sample</div>');
      return;
    }
    const moved = b => (b.rx || []).some(v => v > 0) || (b.tx || []).some(v => v > 0)
      || (b.current_rx || 0) > 0 || (b.current_tx || 0) > 0;
    const load = b => (b.current_rx || 0) + (b.current_tx || 0);
    const peak = b => (b.peak_rx || 0) + (b.peak_tx || 0);
    const active = rows.filter(moved).sort((a, b) => (load(b) - load(a)) || (peak(b) - peak(a)));
    const idle = rows.filter(b => !moved(b)).map(b => b.iface).sort();
    let html = active.map(b => {
      const rx = fmtBytes(b.current_rx || 0) + '/s';
      const tx = fmtBytes(b.current_tx || 0) + '/s';
      const tip = escape(b.iface) + ' · rx ' + rx + ' (peak ' + fmtBytes(b.peak_rx || 0) + '/s) · tx '
        + tx + ' (peak ' + fmtBytes(b.peak_tx || 0) + '/s)';
      return '<div class="spark" title="' + tip + '">'
        + '<span class="spark-label">' + escape(b.iface) + '</span>'
        + sparkLines([{ values: b.rx, color: '#58a6ff' }, { values: b.tx, color: '#3cc7b8' }])
        + '<span class="spark-value spark-pair"><span class="rx">&darr; ' + rx + '</span>'
        + '<span class="tx">&uarr; ' + tx + '</span></span>'
        + '</div>';
    }).join('');
    if (!active.length) html = '<div class="muted">no traffic in the last 120 s</div>';
    if (idle.length) {
      html += '<div class="spark-idle" title="' + escape(idle.join(', ')) + '">'
        + idle.length + ' idle: ' + escape(idle.slice(0, 6).join(', ')) + (idle.length > 6 ? ', …' : '')
        + '</div>';
    }
    setHTML(el, html);
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

  // Probe targets: one row per real target with its trend inline, so the
  // dashboard no longer needs a separate sparkline card per protocol.
  // Internal pseudo-targets are dropped (see targetKind).
  function renderTargets(rows, series) {
    series = series || {};
    const list = (rows || [])
      .map(t => Object.assign({}, t, { kind: t.kind || targetKind(t.target) }))
      .filter(t => t.kind !== 'internal')
      .sort((a, b) => (KIND_ORDER[a.kind] - KIND_ORDER[b.kind]) || a.target.localeCompare(b.target));
    setHTML(document.getElementById('targets-body'), list.map(t => {
      const thr = targetThreshold(t.kind);
      const lossClass = t.loss_pct >= 8 ? 'loss-err' : t.loss_pct >= 2 ? 'loss-warn' : 'loss-ok';
      const lastMs = t.last_rtt_us > 0 ? t.last_rtt_us / 1000 : 0;
      const lastClass = lastMs > thr ? 'loss-warn' : '';
      let baseline = '<span class="muted">learning…</span>';
      if (t.has_baseline) {
        const d = t.baseline_descr || '';
        const cls = d.indexOf('▲') >= 0 ? 'loss-warn' : d.indexOf('▼') >= 0 ? 'loss-ok' : '';
        const band = 'normal band p50 ' + Math.round(t.baseline_p50_ms) + 'ms · p95 '
          + Math.round(t.baseline_p95_ms) + 'ms (n=' + t.baseline_samples + ')';
        baseline = '<span class="' + cls + '" title="' + escape(band) + '">' + escape(d) + '</span>';
      }
      return '<tr>'
        + '<td><span class="probe-kind">' + t.kind + '</span>' + escape(t.target) + '</td>'
        + '<td class="trend-cell" title="dashed line: ' + thr + ' ms threshold">'
        +   sparkLines([{ values: series[t.target], color: '#58a6ff' }], { threshold: thr }) + '</td>'
        + '<td class="num ' + lastClass + '">' + fmtUs(t.last_rtt_us) + '</td>'
        + '<td class="num">' + fmtUs(t.avg_rtt_us) + '</td>'
        + '<td class="num">' + fmtUs(t.p50_rtt_us) + '</td>'
        + '<td class="num">' + fmtUs(t.p95_rtt_us) + '</td>'
        + '<td class="num">' + fmtUs(t.p99_rtt_us) + '</td>'
        + '<td class="num ' + lossClass + '">' + t.loss_pct.toFixed(1) + '%</td>'
        + '<td class="num">' + t.jitter_ms.toFixed(1) + 'ms</td>'
        + '<td>' + baseline + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="10" class="muted">…awaiting first probe</td></tr>');
  }

  function renderDNS(rows, series) {
    series = series || {};
    const thr = Number(lastThresholds.dns_latency_ms) || 120;
    setHTML(document.getElementById('dns-body'), (rows || []).map(d => {
      const lastClass = d.last_us / 1000 > thr ? 'loss-warn' : '';
      return '<tr>'
        + '<td>' + escape(d.name) + '</td>'
        + '<td class="trend-cell" title="dashed line: ' + thr + ' ms threshold">'
        +   sparkLines([{ values: series[d.name], color: '#3cc7b8' }], { threshold: thr }) + '</td>'
        + '<td class="num ' + lastClass + '">' + fmtUs(d.last_us) + '</td>'
        + '<td class="num">' + fmtUs(d.avg_us) + '</td>'
        + '<td class="num">' + d.queries + '</td>'
        + '<td class="num">' + (d.failures > 0 ? '<span class="loss-warn">' + d.failures + '</span>' : '0') + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">…awaiting first query</td></tr>');
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
      const hay = [f.proto, f.iface, f.process, f.a, f.b, f.dns, f.service, flowWhere(f)]
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
      + '<td>' + escape(flowWhere(f) || '-') + '</td>'
      + '<td>' + f.packets + '</td>'
      + '<td>' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="10" class="muted">no flows; start capture in this tab</td></tr>';
  }

  // flowWhere says in a few words where a flow belongs in the appliance:
  // its zone, the tunnel and the person behind it, what address
  // translation did to it, what the load balancer did with it.
  function flowWhere(f) {
    const a = f.attrs;
    if (!a) return '';
    const parts = [];
    if (a.zone) parts.push(a.zone + (a.vrf ? '/' + a.vrf : ''));
    if (a.tunnel) {
      let t = a.tunnel === 'fabric' ? 'fabric' : 'tunnel ' + a.tunnel;
      if (a.peer) t += ' → ' + a.peer + (a.peer_site ? ' @' + a.peer_site : '');
      if (a.path) t += ' via ' + a.path;
      if (a.carrier) t += ' (encrypted)';
      parts.push(t);
    }
    if (a.user) parts.push('user ' + a.user);
    if (a.pre_nat && a.post_nat) parts.push('NAT ' + a.pre_nat.replace(/^\S+ /, '') + ' ⇒ ' + a.post_nat.replace(/^\S+ /, ''));
    if (a.lb_role) {
      let l = (a.lb_role === 'client' ? 'LB client of ' : 'LB backend of ') + (a.lb_service || '?');
      if (a.lb_router) l += ' / ' + a.lb_router;
      if (a.lb_host) l += ' (' + a.lb_host + ')';
      if (a.lb_role === 'client' && a.lb_backend) l += ' → ' + a.lb_backend;
      parts.push(l);
    }
    return parts.join(' · ');
  }

  // Dashboard "Top flows": the five biggest by bytes, then packets - not the
  // first five the backend happens to list.
  function renderTopFlows(rows) {
    const top = (rows || []).slice()
      .sort((a, b) => ((b.bytes || 0) - (a.bytes || 0)) || ((b.packets || 0) - (a.packets || 0)))
      .slice(0, 5);
    setHTML(document.getElementById('flows-body-dash'), top.map(f =>
      '<tr>'
      + '<td>' + escape(f.proto.toUpperCase()) + '</td>'
      + '<td>' + escape(f.iface) + '</td>'
      + '<td>' + escape(f.process || '-') + '</td>'
      + '<td>' + escape(f.a) + ipBadge(f.a_label) + '</td>'
      + '<td>' + escape(f.b) + ipBadge(f.b_label) + '</td>'
      + '<td>' + escape(f.service || '-') + '</td>'
      + '<td class="num">' + f.packets + '</td>'
      + '<td class="num">' + fmtBytes(f.bytes) + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="8" class="muted">…awaiting flows</td></tr>');
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
      loadLib('sankey').then(renderActive, () => {
        host.innerHTML = '<div class="sankey-empty">the Sankey library could not be loaded</div>';
      });
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
      if (name.startsWith(TAG.S)) return '#e275ad'; // service – pink
      return '#3cc7b8';                              // host – teal
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

  // ---- privileged access (Access tab) ----
  // Loaded lazily when the tab is shown and every 5th snapshot poll while it
  // stays active; grants change slowly compared to the 2 s snapshot loop.
  let pamTick = 0;
  let lastWG = [];
  function isPaneActive(name) {
    const p = document.querySelector('[data-pane="' + name + '"]');
    return !!(p && p.classList.contains('active'));
  }
  async function loadAccess() {
    let d;
    try { d = await api('/api/pam'); } catch (e) {
      const s = document.getElementById('pam-summary');
      if (s) s.textContent = 'unavailable: ' + (e.message || e);
      return;
    }
    if (!d) return;
    renderAccess(d);
  }
  function fmtWindow(g) {
    if (g.state === 'active') {
      const left = Math.max(0, Math.round((new Date(g.ends_at) - Date.now()) / 60000));
      return 'until ' + new Date(g.ends_at).toLocaleTimeString() + ' (' + left + ' min left)';
    }
    if (g.state === 'pending') return (g.ttl_sec / 60) + ' min requested';
    if (g.ended_at && g.ended_at !== '0001-01-01T00:00:00Z') return 'ended ' + new Date(g.ended_at).toLocaleString();
    return '-';
  }
  function renderAccess(d) {
    const ov = d.overview || {};
    const resById = {};
    (ov.resources || []).forEach(r => { resById[r.id] = r; });
    const summary = document.getElementById('pam-summary');
    if (summary) {
      const active = (ov.grants || []).filter(g => g.state === 'active').length;
      const pending = (ov.grants || []).filter(g => g.state === 'pending').length;
      summary.textContent = d.me + ' (' + d.role + (d.mfa ? ', MFA' : '') + ') · ' + active + ' active · ' + pending + ' pending · tunnel ' + (ov.device || 'wg0');
    }
    const reqCard = document.getElementById('pam-request-card');
    if (reqCard) reqCard.hidden = !d.can_request;
    document.querySelectorAll('[data-pane="access"] [data-admin-only]').forEach(el => { el.hidden = !d.is_admin; });

    const resOpts = (ov.resources || []).map(r => '<option value="' + escape(r.id) + '">' + escape(r.name) + ' (' + escape(r.cidr) + ')</option>').join('');
    ['pam-res'].forEach(id => {
      const sel = document.getElementById(id);
      if (!sel) return;
      const cur = sel.value;
      sel.innerHTML = resOpts || '<option value="">no resources yet</option>';
      if (cur) sel.value = cur;
    });

    document.getElementById('pam-grants-body').innerHTML = (ov.grants || []).map(g => {
      const res = resById[g.resource_id];
      const mine = g.user === d.me;
      const actions = [];
      if (g.state === 'pending' && d.can_approve && !mine) {
        actions.push('<button class="btn btn-small btn-go" data-action="pam-approve" data-id="' + escape(g.id) + '">approve</button>');
        actions.push('<button class="btn btn-small" data-action="pam-deny" data-id="' + escape(g.id) + '">deny</button>');
      }
      if (g.state === 'active' && mine) {
        const url = (d.launch_urls || {})[g.id];
        if (url) actions.push('<a class="btn btn-small btn-go" href="' + escape(url) + '" target="_blank" rel="noopener">open session</a>');
        if (res && res.kind === 'ssh') actions.push('<button class="btn btn-small" data-action="pam-ssh-cert" data-id="' + escape(g.id) + '" title="sign your SSH public key for this grant window">ssh cert</button>');
      }
      if ((g.state === 'active' || g.state === 'pending') && (mine || d.can_approve)) {
        actions.push('<button class="btn btn-small btn-danger" data-action="pam-revoke" data-id="' + escape(g.id) + '">' + (g.state === 'active' ? 'revoke' : 'withdraw') + '</button>');
      }
      const stateCls = g.state === 'active' ? 'on' : (g.state === 'pending' ? 'warn' : 'off');
      return '<tr' + (g.break_glass ? ' class="warn"' : '') + '>'
        + '<td><code title="' + escape(g.justification) + '">' + escape(g.id.replace('grant-', '')) + '</code>' + (g.break_glass ? ' 🚨' : '') + (g.ticket ? ' <span class="muted">' + escape(g.ticket) + '</span>' : '') + '</td>'
        + '<td>' + escape(g.user) + '</td>'
        + '<td>' + escape(res ? res.name : g.resource_id) + '</td>'
        + '<td><span class="status-pill ' + stateCls + '">' + escape(g.state) + '</span>' + (g.end_reason ? '<div class="muted">' + escape(g.end_reason) + '</div>' : '') + '</td>'
        + '<td>' + escape(fmtWindow(g)) + '</td>'
        + '<td>' + escape(g.approved_by || '-') + '</td>'
        + '<td>' + (g.observed_flows ? g.observed_flows + ' flows · ' + fmtBytes(g.observed_bytes) : '-') + (g.capture_id ? '<div class="muted">pcap ' + escape(g.capture_id) + '</div>' : '') + '</td>'
        + '<td>' + actions.join(' ') + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="8" class="muted">no grants yet</td></tr>';

    document.getElementById('pam-res-body').innerHTML = (ov.resources || []).map(r => {
      const port = r.port_lo ? (r.proto + '/' + r.port_lo + (r.port_hi ? '-' + r.port_hi : '')) : (r.proto || 'any');
      return '<tr>'
        + '<td>' + escape(r.name) + '</td>'
        + '<td>' + escape(r.kind) + '</td>'
        + '<td><code>' + escape(r.cidr) + ' ' + escape(port) + '</code></td>'
        + '<td>' + escape(r.login || '-') + '</td>'
        + '<td>' + escape(r.broker_ref || '-') + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="5" class="muted">no resources yet: Access → Resources</td></tr>';

    document.getElementById('pam-pol-body').innerHTML = (ov.policies || []).map(p => {
      const res = resById[p.resource_id];
      return '<tr>'
        + '<td>' + escape(p.name) + '</td>'
        + '<td><code>' + escape(p.subject) + '</code></td>'
        + '<td>' + escape(res ? res.name : p.resource_id) + '</td>'
        + '<td>' + Math.round(p.max_ttl_sec / 60) + ' min</td>'
        + '<td>' + (p.requires_approval ? 'yes' : 'auto') + '</td>'
        + '<td>' + (p.requires_mfa ? 'yes' : '-') + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="6" class="muted">no policy to ask under yet: Access → Policies</td></tr>';

    const chain = document.getElementById('pam-chain');
    if (chain) {
      chain.textContent = ov.chain_broken_at ? 'BROKEN at row ' + ov.chain_broken_at : (ov.chain_checked + ' events verified');
      chain.className = ov.chain_broken_at ? 'status-pill off' : 'status-pill on';
    }
    const caEl = document.getElementById('pam-ssh-ca');
    if (caEl) {
      caEl.textContent = d.ssh_ca_key ? d.ssh_ca_key + '   # ' + d.ssh_ca_fp : 'SSH CA unavailable';
    }
    const brokerEl = document.getElementById('pam-broker');
    if (brokerEl) brokerEl.textContent = d.broker_ready ? 'Guacamole brokering on' : 'Guacamole brokering off (set the API credentials in Settings)';
    document.getElementById('pam-events-body').innerHTML = (ov.events || []).map(e => '<tr>'
      + '<td>' + escape(new Date(e.ts).toLocaleString()) + '</td>'
      + '<td>' + escape(e.actor) + '</td>'
      + '<td>' + escape(e.action) + '</td>'
      + '<td><code>' + escape((e.grant_id || '').replace('grant-', '')) + '</code></td>'
      + '<td class="muted">' + escape(e.detail || '') + '</td>'
      + '</tr>').join('') || '<tr><td colspan="5" class="muted">no access events yet</td></tr>';
  }

  // ---- identity ----
  // me is the logged-in user as reported by /api/me; the role decides which
  // admin-only cards render. The server enforces every permission regardless.
  let me = null;
  async function loadMe() {
    try {
      me = await api('/api/me');
    } catch (_) { me = null; }
    const badge = document.getElementById('me-badge');
    if (badge) {
      badge.textContent = me ? (me.user + ' · ' + me.role + (me.mfa_enrolled ? ' · MFA' : '')) : '';
      badge.title = me && !me.tls ? 'plain HTTP - enable --tls-auto before exposing this UI' : 'signed-in user · role';
    }
    const sum = document.getElementById('me-summary');
    if (sum && me) sum.textContent = me.user + ' (' + me.role + ')' + (me.mfa_enrolled ? ' · MFA enrolled' : ' · no MFA');
    document.querySelectorAll('[data-admin-only]').forEach(el => { el.hidden = !(me && me.role === 'admin'); });
    document.body.dataset.role = me ? me.role : '';
  }

  // showTOTP renders a one-shot otpauth:// URI (and a QR when an encoder is on
  // the page). Nothing here is sent back to the server.
  function showTOTP(uri) {
    const box = document.getElementById('totp-result');
    if (!box) return;
    if (!uri) { box.hidden = true; return; }
    document.getElementById('totp-uri').textContent = uri;
    renderQR(document.getElementById('totp-qr'), uri, 200);
    box.hidden = false;
    box.scrollIntoView({ block: 'nearest' });
  }
  function hideTOTP() {
    const box = document.getElementById('totp-result');
    if (box) box.hidden = true;
  }

  function renderFirewallPolicy(p) {
    const mode = document.getElementById('fw-policy-mode');
    const summary = document.getElementById('fw-policy-summary');
    if (!mode) return;
    if (!p) {
      mode.textContent = 'unavailable';
      summary.textContent = 'netops not initialized - firewall management is off';
      return;
    }
    if (!p.available) {
      mode.textContent = 'unavailable';
      summary.textContent = p.error || 'policy file could not be loaded';
      return;
    }
    mode.textContent = p.enforce ? 'DEFAULT-DENY (enforcing)' : 'default-accept (permissive)';
    mode.className = p.enforce ? 'status-pill on' : '';
    const bits = [];
    bits.push(p.rule_count + ' rule' + (p.rule_count === 1 ? '' : 's'));
    if (p.drift_error) bits.push('kernel state unreadable (' + p.drift_error + ')');
    else if (p.inert && !p.table_exists) bits.push('inert - nothing installed until the first rule or default-deny');
    else bits.push(p.in_sync ? 'kernel in sync' : 'DRIFT: ' + (p.drift_detail || []).join('; '));
    if (!p.writes_allowed) bits.push('netops writes disabled (read-only)');
    if (p.last_apply) bits.push('applied ' + new Date(p.last_apply).toLocaleTimeString());
    if (p.last_error) bits.push('last error: ' + p.last_error);
    if (p.imported) bits.push('imported ' + p.imported + ' pre-policy entries');
    bits.push('file ' + p.path);
    summary.textContent = bits.join(' · ');
    summary.className = (p.in_sync || p.drift_error) && !p.last_error ? 'muted' : 'muted warn';
  }

  function fwMatchText(r) {
    // Strip the leading chain and trailing action from the nft-style line so
    // the table shows just the match.
    let t = r.text || '';
    if (t.startsWith(r.chain + ' ')) t = t.slice(r.chain.length + 1);
    const tail = ' ' + r.action;
    if (t.endsWith(tail)) t = t.slice(0, -tail.length);
    if (t.endsWith(' log')) t = t.slice(0, -4);
    return t.trim() || 'any';
  }

  // lastFWPolicy lets the rule table tell "not installed because the policy is
  // inert" apart from real drift.
  let lastFWPolicy = null;
  function renderFirewall(rules, system, ruleCounters) {
    const inertIdle = !!(lastFWPolicy && lastFWPolicy.inert && !lastFWPolicy.table_exists);
    document.getElementById('fw-rules-body').innerHTML = (rules || []).map(r => {
      const notLive = !r.live && !inertIdle;
      const cls = (r.baseline ? ' class="dim"' : '') + (notLive ? ' title="desired but not live (drift)"' : '');
      const userAttr = '';
      // Only rules made by hand before the configuration existed can be
      // deleted here; everything else belongs to its subsystem.
      const mine = !r.baseline && (!r.owner || r.owner === 'user');
      const actions = r.baseline ? '<span class="muted">baseline</span>'
        : mine ? '<button class="btn btn-small btn-danger" data-action="fw-del" data-id="' + escape(r.id) + '" data-text="' + escape(r.text) + '">del</button>'
        : '<span class="muted">' + escape(r.owner === 'model' ? 'configuration' : r.owner) + '</span>';
      const actionCls = (r.action === 'drop' || r.action === 'reject') ? ' class="status-pill off"' : '';
      return '<tr' + cls + userAttr + '>'
        + '<td>' + escape(r.chain) + '</td>'
        + '<td><span' + actionCls + '>' + escape(r.action.toUpperCase()) + (r.log ? ' +log' : '') + '</span></td>'
        + '<td><code>' + escape(fwMatchText(r)) + '</code></td>'
        + '<td>' + escape(r.owner === 'user' ? '' : r.owner) + (notLive ? ' <span class="status-pill off">not live</span>' : '') + '</td>'
        + '<td>' + escape(r.comment || '') + '</td>'
        + '<td>' + (r.has_counter ? r.packets : '-') + '</td>'
        + '<td>' + (r.has_counter ? fmtBytes(r.bytes) : '-') + '</td>'
        + '<td>' + actions + '</td>'
        + '</tr>';
    }).join('') || '<tr><td colspan="8" class="muted">no rules - add one above</td></tr>';

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
      + '<td>' + (!n.owner || n.owner === 'user'
        ? '<button class="btn btn-small btn-danger" data-action="nat-del" data-id="' + escape(n.id) + '" data-proto="' + escape(n.proto) + '" data-port="' + n.wan_port + '">del</button>'
        : '<span class="muted">' + escape(n.owner === 'model' ? 'configuration' : n.owner) + '</span>') + '</td>'
      + '</tr>'
    ).join('') || '<tr><td colspan="5" class="muted">no port forwards configured</td></tr>';
  }

  // Tiny unicode sparkline for per-peer throughput history.
  function wgSpark(values) {
    const bars = '▁▂▃▄▅▆▇█';
    const v = (values || []).filter(x => typeof x === 'number');
    if (!v.length) return '<span class="muted">-</span>';
    const max = Math.max.apply(null, v) || 1;
    return v.map(x => bars[Math.min(bars.length - 1, Math.floor((x / max) * (bars.length - 1)))]).join('');
  }

  // wgDriftBadge renders the live-vs-netplan drift indicator for a peer.
  function wgDriftBadge(drift) {
    switch (drift) {
      case 'not-persistent': return ' <span class="status-pill warn" title="live in kernel but not in netplan - lost on next apply/reboot">not persistent</span>';
      case 'config-only':    return ' <span class="status-pill off" title="declared in netplan but not up on the device">config only</span>';
      case 'config-mismatch':return ' <span class="status-pill warn" title="AllowedIPs differ live vs netplan">config drift</span>';
      default: return '';
    }
  }

  function wgSevClass(sev) {
    if (sev === 'CRITICAL' || sev === 'ERROR') return 'off';
    if (sev === 'WARN') return 'warn';
    return 'on';
  }

  // renderWGStats fills the WireGuard-only KPI strip from the WG snapshot.
  // rx/tx errors + drops are interface-level (WireGuard has no per-peer error
  // counters) and summed across every wg device for the global view.
  function renderWGStats(devs) {
    const el = document.getElementById('wg-stats');
    if (!el) return;
    let peers = 0, healthy = 0, warn = 0, down = 0, never = 0, rx = 0, tx = 0;
    let rxErr = 0, txErr = 0, rxDrop = 0, txDrop = 0;
    for (const d of devs) {
      rxErr += (d.rx_errors || 0); txErr += (d.tx_errors || 0);
      rxDrop += (d.rx_dropped || 0); txDrop += (d.tx_dropped || 0);
      for (const p of (d.peers || [])) {
        peers++;
        rx += (p.rx_bytes || 0);
        tx += (p.tx_bytes || 0);
        switch (p.severity) {
          case 'OK': healthy++; break;
          case 'WARN': warn++; break;
          case 'ERROR': down++; break;
          case 'CRITICAL': never++; break;
        }
      }
    }
    const unhealthy = warn + down + never;
    const healthState = peers === 0 ? '' : (down + never > 0 ? 'err' : (warn > 0 ? 'warn' : 'ok'));
    const errTotal = rxErr + txErr;
    const dropTotal = rxDrop + txDrop;
    el.innerHTML = ''
      + kpiTile('Devices', String(devs.length), { sub: 'wg interfaces' })
      + kpiTile('Peers', String(peers), { sub: healthy + ' healthy', state: healthState })
      + kpiTile('Degraded', String(unhealthy), {
          state: unhealthy ? (down + never ? 'err' : 'warn') : '',
          sub: warn + ' stale · ' + down + ' down · ' + never + ' never' })
      + kpiTile('RX', fmtBytes(rx), { arrow: 'down', sub: 'total received' })
      + kpiTile('TX', fmtBytes(tx), { arrow: 'up', sub: 'total sent' })
      + kpiTile('Errors', String(errTotal), {
          state: errTotal ? 'err' : '', sub: rxErr + ' rx · ' + txErr + ' tx (iface)' })
      + kpiTile('Drops', String(dropTotal), {
          state: dropTotal ? 'warn' : '', sub: rxDrop + ' rx · ' + txDrop + ' tx (iface)' });
  }

  // renderWGDashboard fills the dashboard's WireGuard section: an overall
  // "healthy/degraded" line + KPI tiles (D2) and a per-interface summary (D1).
  function renderWGDashboard(devices) {
    const card = document.getElementById('wg-dash-card');
    if (!card) return;
    const devs = devices || [];
    if (!devs.length) { card.hidden = true; return; }
    card.hidden = false;

    let ifaces = devs.length, peers = 0, active = 0, stale = 0, drift = 0, rx = 0, tx = 0, down = 0;
    for (const d of devs) {
      if (!d.up) down++;
      drift += (d.drift_count || 0);
      rx += (d.rx_bytes || 0); tx += (d.tx_bytes || 0);
      for (const p of (d.peers || [])) {
        peers++;
        if (p.severity === 'OK') active++;
        else if (p.severity === 'WARN' || p.severity === 'ERROR') stale++;
      }
    }
    const bad = down > 0 || stale > 0 || drift > 0;
    const overall = document.getElementById('wg-dash-overall');
    if (overall) {
      overall.innerHTML = bad
        ? '<span class="severity severity-WARN">degraded</span>'
        : '<span class="severity severity-INFO">healthy</span>';
    }
    document.getElementById('wg-dash-kpis').innerHTML = ''
      + kpiTile('Tunnels', String(ifaces), { state: down ? 'err' : 'ok', sub: down + ' down' })
      + kpiTile('Peers', active + '/' + peers, { state: stale ? 'warn' : 'ok', sub: 'active / total' })
      + kpiTile('Stale', String(stale), { state: stale ? 'warn' : '', sub: 'handshake stale/down' })
      + kpiTile('Drift', String(drift), { state: drift ? 'warn' : '', sub: 'live ≠ netplan' })
      + kpiTile('RX', fmtBytes(rx), { arrow: 'down', sub: 'total' })
      + kpiTile('TX', fmtBytes(tx), { arrow: 'up', sub: 'total' });

    document.getElementById('wg-dash-ifaces').innerHTML = devs.map(d => {
      const a = (d.peers || []).filter(p => p.severity === 'OK').length;
      const link = d.up ? '<span class="status-pill on">up</span>' : '<span class="status-pill off">down</span>';
      const dr = d.drift_count > 0 ? ' <span class="status-pill warn">drift ' + d.drift_count + '</span>' : '';
      const nm = d.label ? escape(d.label) + ' (' + escape(d.name) + ')' : escape(d.name);
      return '<div class="wg-dash-row"><b>' + nm + '</b> ' + link + dr
        + ' <span class="muted">:' + d.listen_port + ' · ' + a + '/' + (d.peers || []).length + ' peers · '
        + fmtBytes(d.rx_bytes) + '↓ ' + fmtBytes(d.tx_bytes) + '↑</span></div>';
    }).join('');
  }

  function renderWireGuard(devices) {
    const el = document.getElementById('wg-body');
    const devs = devices || [];
    renderWGStats(devs);
    if (!el) return;
    if (!devs.length) {
      el.innerHTML = '<p class="muted">no WireGuard devices found (reading state needs CAP_NET_ADMIN; a tunnel may still be up)</p>';
      return;
    }
    // Preserve each table's horizontal/vertical scroll across the 2s re-render:
    // capture by device name, rebuild, then restore.
    const scrollPos = {};
    el.querySelectorAll('.wg-table-wrap[data-dev]').forEach(w => {
      scrollPos[w.dataset.dev] = { x: w.scrollLeft, y: w.scrollTop };
    });
    el.innerHTML = devs.map(d => {
      const linkPill = d.up
        ? '<span class="status-pill ' + (d.running ? 'on' : 'warn') + '">' + (d.running ? 'UP' : 'UP (no carrier)') + '</span>'
        : '<span class="status-pill off">DOWN</span>';
      // Device health pill from tx/rx-error health (+ link state).
      const devHealth = d.health || 'OK';
      const healthPill = '<span class="status-pill ' + wgSevClass(devHealth) + '" title="device health from tx/rx errors + link state">'
        + escape(devHealth) + '</span>';
      const errTot = (d.rx_errors || 0) + (d.tx_errors || 0);
      const dropTot = (d.rx_dropped || 0) + (d.tx_dropped || 0);
      const growing = (d.err_delta || 0) > 0 ? ' <span class="loss-warn">▲+' + d.err_delta + '</span>' : '';
      const errBadge = errTot > 0 ? ' · <span class="' + (d.err_delta > 0 ? 'loss-warn' : 'muted') + '">err ' + errTot + growing + '</span>' : '';
      const dropGrow = (d.drop_delta || 0) > 0 ? ' <span class="warn">▲+' + d.drop_delta + '</span>' : '';
      const dropBadge = dropTot > 0 ? ' · <span class="muted">drop ' + dropTot + dropGrow + '</span>' : '';
      // Netplan reconciliation for the device header.
      const npPill = !d.netplan_known
        ? ' <span class="status-pill muted" title="not found in a parsed netplan file">no netplan</span>'
        : (d.drift_count > 0
            ? ' <span class="status-pill warn" title="peers whose live state differs from netplan">drift ' + d.drift_count + '</span>'
            : ' <span class="status-pill on" title="live matches netplan">in sync</span>');
      const cfgAddr = d.configured_address ? ' · cfg ' + escape(d.configured_address) : '';
      const label = d.label ? '<b>' + escape(d.label) + '</b> <code class="muted">' + escape(d.name) + '</code>' : 'wg <b>' + escape(d.name) + '</b>';
      const delBtn = d.netplan_known
        ? ' <button class="btn btn-small btn-danger" data-action="wg-iface-delete" data-dev="' + escape(d.name) + '" title="delete the Testudo netplan for this interface">delete</button>'
        : '';
      const ifaceBtns = '<span class="wg-iface-btns">'
        + '<button class="btn btn-small" data-action="wg-iface-tune" data-dev="' + escape(d.name) + '" title="apply the recommended max-performance profile (MTU 1420, txqueuelen 1000, socket buffers)">⚡ tune</button> '
        + '<button class="btn btn-small" data-action="wg-iface-mtu" data-dev="' + escape(d.name) + '" data-mtu="' + (d.mtu || 0) + '" title="set MTU manually (lower to 1380/1280 if errors persist)">MTU</button> '
        + '<button class="btn btn-small" data-action="wg-iface-rename" data-dev="' + escape(d.name) + '" data-label="' + escape(d.label || '') + '">rename</button> '
        + '<button class="btn btn-small" data-action="wg-iface-restart" data-dev="' + escape(d.name) + '">restart</button>'
        + delBtn
        + '</span>';
      const mtu = d.mtu ? ' · mtu ' + d.mtu : '';
      const txq = d.txqlen ? '/txq ' + d.txqlen : '';
      const head = '<h3 class="wg-dev-head">' + label + ' ' + linkPill + ' ' + healthPill + npPill
        + ' · listen :' + d.listen_port + cfgAddr + mtu + txq + ' · ' + (d.peers || []).length + ' peers'
        + ' · rx ' + fmtBytes(d.rx_bytes) + ' / tx ' + fmtBytes(d.tx_bytes)
        + errBadge + dropBadge + ' ' + ifaceBtns + '</h3>';
      const rows = (d.peers || []).map(p => {
        const hs = '<span class="status-pill ' + wgSevClass(p.severity) + '">' + escape(p.handshake) + '</span>';
        const health = p.health || p.severity || 'OK';
        const healthCell = '<span class="status-pill ' + wgSevClass(health) + '" title="worst of handshake + device tx/rx-error health">' + escape(health) + '</span>';
        const allowed = (p.allowed_ips || []).join(', ');
        // Name primary, key on hover.
        const nameCell = p.name
          ? '<b title="' + escape(p.public_key) + '">' + escape(p.name) + '</b> <code class="muted">' + escape(p.short) + '</code>'
          : '<code title="' + escape(p.public_key) + '">' + escape(p.short) + '</code>';
        const drift = wgDriftBadge(p.drift);
        return '<tr>'
          + '<td>' + nameCell + '</td>'
          + '<td>' + healthCell + drift + '</td>'
          + '<td>' + escape(p.endpoint || '-') + '</td>'
          + '<td>' + hs + '</td>'
          + '<td><code>' + escape(allowed || '-') + '</code></td>'
          + '<td>' + fmtBytes(p.rx_bytes) + '</td>'
          + '<td>' + fmtBytes(p.tx_bytes) + '</td>'
          + '<td class="wg-spark">' + wgSpark(p.tx_history) + '</td>'
          + '<td class="wg-actions">'
            + '<button class="btn btn-small" data-action="wg-edit"'
              + ' data-pubkey="' + escape(p.public_key) + '" data-short="' + escape(p.name || p.short) + '"'
              + ' data-endpoint="' + escape(p.endpoint || '') + '"'
              + ' data-keepalive="' + (p.keepalive_sec || 0) + '"'
              + ' data-allowed="' + escape((p.allowed_ips || []).join(', ')) + '">edit</button> '
            + '<button class="btn btn-small btn-danger" data-action="wg-deprovision" data-pubkey="' + escape(p.public_key) + '" data-short="' + escape(p.name || p.short) + '">remove</button>'
          + '</td>'
          + '</tr>';
      }).join('') || '<tr><td colspan="9" class="muted">no peers configured</td></tr>';
      return head + '<div class="table-wrap wg-table-wrap" data-dev="' + escape(d.name) + '"><table>'
        + '<thead><tr><th>Peer</th><th>Health</th><th>Endpoint</th><th>Handshake</th><th>Allowed IPs</th><th>RX</th><th>TX</th><th>TX bps</th><th></th></tr></thead>'
        + '<tbody>' + rows + '</tbody></table></div>';
    }).join('');
    // Restore scroll positions captured before the rebuild.
    el.querySelectorAll('.wg-table-wrap[data-dev]').forEach(w => {
      const pos = scrollPos[w.dataset.dev];
      if (pos) { w.scrollLeft = pos.x; w.scrollTop = pos.y; }
    });
  }

  // showWireGuardConfig displays the one-shot server-side-keygen client config.
  // The config (with its PRIVATE key) lives only in the browser; the QR is
  // rendered client-side and nothing is sent back to the server.
  function showWireGuardConfig(ip, config) {
    const modal = document.getElementById('wg-config-modal');
    if (!modal) return;
    document.getElementById('wg-config-ip').textContent = ip || '';
    document.getElementById('wg-config-text').textContent = config || '';
    const qr = document.getElementById('wg-qr');
    if (qr) {
      // QR generation is a client-side concern (never server-side): the
      // config with its private key never leaves this page.
      renderQR(qr, config || '', 240);
    }
    modal.hidden = false;
  }

  function hideWireGuardConfig() {
    const modal = document.getElementById('wg-config-modal');
    if (!modal) return;
    // Wipe the secret from the DOM on dismiss.
    document.getElementById('wg-config-text').textContent = '';
    const qr = document.getElementById('wg-qr');
    if (qr) qr.innerHTML = '';
    modal.hidden = true;
  }

  // openWGEdit populates and shows the full peer-edit modal from the peer's
  // current endpoint / allowed IPs, seeding the Allowed-IPs combo box.
  function openWGEdit(pubkey, short, endpoint, allowed, keepalive) {
    const modal = document.getElementById('wg-edit-modal');
    if (!modal) return;
    modal.dataset.pubkey = pubkey || '';
    document.getElementById('wg-edit-short').textContent = short || '';
    document.getElementById('wg-edit-endpoint').value = endpoint || '';
    const ka = document.getElementById('wg-edit-keepalive');
    if (ka) ka.value = (keepalive && keepalive > 0) ? String(keepalive) : '';
    const values = (allowed || '').split(',').map(s => s.trim()).filter(Boolean);
    wgCombo.setValues(values);
    modal.hidden = false;
  }

  // ---- Netplan file browser/editor --------------------------------
  let wgNetplanFiles = [];
  async function loadNetplanFiles() {
    const res = await post('/api/wireguard/netplan/list', {});
    wgNetplanFiles = (res && res.files) || [];
    const sel = document.getElementById('wg-np-select');
    const editor = document.getElementById('wg-np-editor');
    if (!sel || !editor) return;
    sel.innerHTML = wgNetplanFiles.map((f, i) =>
      '<option value="' + escape(f.path) + '" data-i="' + i + '">' + escape(f.name) + (f.managed ? ' (testudo)' : '') + '</option>'
    ).join('') || '<option value="">no netplan files found</option>';
    showSelectedNetplan();
  }
  function showSelectedNetplan() {
    const sel = document.getElementById('wg-np-select');
    const editor = document.getElementById('wg-np-editor');
    const managed = document.getElementById('wg-np-managed');
    if (!sel || !editor) return;
    const f = wgNetplanFiles.find(x => x.path === sel.value);
    editor.value = f ? f.content : '';
    if (managed) managed.textContent = f && f.managed ? 'managed by testudo' : '';
  }

  // ---- Allowed-IPs multi-select combo box (EUI-style token input) ---
  // Pills for each selected CIDR, a filterable dropdown of suggestions, and
  // type-to-add for custom values. Self-contained; no external dependency.
  const wgCombo = (function () {
    const state = { values: [], active: -1 };
    const els = () => ({
      root: document.getElementById('wg-allowed-combo'),
      pills: document.getElementById('wg-allowed-pills'),
      input: document.getElementById('wg-allowed-input'),
      menu: document.getElementById('wg-allowed-menu'),
    });

    // Suggestions drawn from the persisted WireGuard settings.
    function suggestions() {
      const t = lastThresholds || {};
      const out = ['0.0.0.0/0', '::/0'];
      if (t.wireguard_tunnel_subnet) out.push(t.wireguard_tunnel_subnet);
      if (t.wireguard_server_addr) out.push(t.wireguard_server_addr);
      (t.wireguard_lan_subnets || '').split(',').map(s => s.trim()).filter(Boolean).forEach(s => out.push(s));
      return out.filter((v, i) => out.indexOf(v) === i); // de-dupe, keep order
    }

    function setValues(vals) {
      state.values = (vals || []).slice();
      state.active = -1;
      const { input } = els();
      if (input) input.value = '';
      renderPills();
      hideMenu();
    }
    function getValues() { return state.values.slice(); }

    function renderPills() {
      const { pills, input } = els();
      if (!pills || !input) return;
      pills.querySelectorAll('.combo-pill').forEach(n => n.remove());
      state.values.forEach((v, i) => {
        const pill = document.createElement('span');
        pill.className = 'combo-pill';
        pill.innerHTML = escape(v) + ' <button type="button" data-i="' + i + '" aria-label="remove">×</button>';
        pills.insertBefore(pill, input);
      });
    }

    function add(v) {
      v = (v || '').trim();
      if (!v || state.values.includes(v)) return;
      state.values.push(v);
      const { input } = els();
      if (input) input.value = '';
      renderPills();
      renderMenu();
    }
    function removeAt(i) { state.values.splice(i, 1); renderPills(); renderMenu(); }

    function candidates() {
      const { input } = els();
      const q = (input ? input.value : '').trim().toLowerCase();
      return suggestions().filter(s => !state.values.includes(s) && (!q || s.toLowerCase().includes(q)));
    }

    function renderMenu() {
      const { input, menu } = els();
      if (!input || !menu) return;
      const q = input.value.trim();
      const cands = candidates();
      let html = cands.map((s, i) =>
        '<div class="combo-opt mono' + (i === state.active ? ' active' : '') + '" data-val="' + escape(s) + '">' + escape(s) + '</div>'
      ).join('');
      // Offer to create a custom value that isn't already an option/selected.
      if (q && !suggestions().includes(q) && !state.values.includes(q)) {
        const idx = cands.length;
        html += '<div class="combo-opt' + (idx === state.active ? ' active' : '') + '" data-val="' + escape(q) + '">'
          + '<span class="combo-create">+ add</span> <span class="mono">' + escape(q) + '</span></div>';
      }
      menu.innerHTML = html || '<div class="combo-empty">no matches</div>';
      menu.hidden = false;
    }
    function hideMenu() { const { menu } = els(); if (menu) { menu.hidden = true; state.active = -1; } }

    // menu rows in current order (candidates + optional create row).
    function menuRows() {
      const { menu } = els();
      return menu ? Array.from(menu.querySelectorAll('.combo-opt')) : [];
    }

    function init() {
      const { root, pills, input, menu } = els();
      if (!root || !input) return;
      input.addEventListener('focus', renderMenu);
      input.addEventListener('input', () => { state.active = -1; renderMenu(); });
      input.addEventListener('keydown', (e) => {
        const rows = menuRows();
        if (e.key === 'ArrowDown') { e.preventDefault(); state.active = Math.min(rows.length - 1, state.active + 1); renderMenu(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); state.active = Math.max(0, state.active - 1); renderMenu(); }
        else if (e.key === 'Enter') {
          e.preventDefault();
          const rowsNow = menuRows();
          if (state.active >= 0 && rowsNow[state.active]) add(rowsNow[state.active].dataset.val);
          else if (input.value.trim()) add(input.value);
        } else if (e.key === 'Escape') { hideMenu(); }
        else if (e.key === 'Backspace' && input.value === '' && state.values.length) { removeAt(state.values.length - 1); }
        else if (e.key === ',' || e.key === ' ') {
          // comma/space commits the typed token, matching paste-friendly entry.
          if (input.value.trim()) { e.preventDefault(); add(input.value); }
        }
      });
      // Click a menu option.
      menu.addEventListener('mousedown', (e) => {
        const opt = e.target.closest('.combo-opt');
        if (!opt) return;
        e.preventDefault();
        add(opt.dataset.val);
        input.focus();
      });
      // Remove a pill.
      pills.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-i]');
        if (!btn) return;
        removeAt(parseInt(btn.dataset.i, 10));
        input.focus();
      });
      // Clicking anywhere in the box focuses the input.
      pills.addEventListener('mousedown', (e) => { if (e.target === pills) input.focus(); });
      // Close the menu on outside click.
      document.addEventListener('mousedown', (e) => { if (!root.contains(e.target)) hideMenu(); });
    }

    return { init, setValues, getValues };
  })();

  // Prefill the netplan interface card once from persisted settings; leave the
  // operator's edits in place after that.
  let wgIfaceLoaded = false;
  function prefillWGInterface(t) {
    if (wgIfaceLoaded || !t) return;
    wgIfaceLoaded = true;
    const addr = document.getElementById('wg-if-addr');
    const port = document.getElementById('wg-if-port');
    const path = document.getElementById('wg-if-path');
    if (addr && !addr.value) addr.value = t.wireguard_server_addr || '';
    if (port && !port.value) port.value = t.wireguard_listen_port || 51820;
    if (path && !path.value) path.value = t.wireguard_netplan_path || '/etc/netplan/60-testudo-wg.yaml';
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
    document.getElementById('s-guac-api-user').value = t.guacamole_api_user || '';
    document.getElementById('s-guac-rec').value = t.guacamole_recording_path || '';
    document.getElementById('s-guac-ts').value = t.guacamole_typescript_path || '';
    // The API password is never sent to the page; blank means "keep".
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
  // The snapshot is fetched every 2 s, but only the visible pane renders:
  // hidden panes (the d3 Sankey layout above all) cost nothing until they
  // are opened, and a tab switch renders from the last snapshot at once.
  // Polling pauses while the browser tab is in the background, except while
  // a default-deny commit-confirm is pending (the confirm rides on a poll).
  let refreshing = false;
  let lastThresholds = {};
  let lastSnap = null;
  const PANE_RENDERERS = {
    dashboard: s => {
      renderGrade(s.grade || {});
      renderKpis(s);
      renderWGDashboard(s.wireguard);
      renderBandwidth(s.bandwidth || []);
      renderWiFi(s.wifi);
      renderTargets(s.targets, s.latency_series);
      renderDNS(s.dns, s.dns_series);
      renderTopFlows(s.flows);
    },
    flows: s => {
      renderCapture(s.capture || { running: false, ifaces: [] });
      renderFlows(s.flows);
      renderFlowsSankey(s.flows);
    },
    talkers:   s => renderTalkers(s.top_hosts, s.top_processes, s.top_services),
    devices:   s => { renderDevices(s.devices); renderNeighbours(s.neighbours, s.ip_conflicts); },
    ifaces:    s => { renderIfaces(s.ifaces, s.wifi); renderWatcher(s.watcher); },
    wifi:      s => renderWiFiDetail(s.wifi),
    routes:    s => { renderRoutes(s.routes); renderWatcher(s.watcher); },
    firewall:  s => renderFirewall(s.filter_rules, s.firewall, s.firewall_rules),
    nat:       s => { renderNAT(s.nat); renderConntrack(s.conntrack, s.thresholds && s.thresholds.allow_netops_write); },
    wireguard: s => renderWireGuard(s.wireguard),
    tcpdump:   s => renderTCPDump(s.tcpdump),
    alerts:    s => renderAlerts(s.anomalies),
    health:    s => renderHealth(s.subsystems, s.audit, s.privsep),
    settings:  s => renderIPFIX(s.ipfix),
  };
  function activePaneName() {
    const p = document.querySelector('.pane.active');
    return p ? p.dataset.pane : 'dashboard';
  }
  function renderActive() {
    const fn = lastSnap && PANE_RENDERERS[activePaneName()];
    if (!fn) return;
    try { fn(lastSnap); } catch (e) { console.error('render failed', e); }
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const snap = await api('/api/snapshot');
      if (!snap) return;
      lastSnap = snap;
      lastThresholds = snap.thresholds || {};
      document.getElementById('session-id').textContent = snap.session || '-';
      document.getElementById('uptime').textContent = snap.uptime || '-';
      const upTop = document.getElementById('uptime-top');
      if (upTop) upTop.textContent = snap.uptime || '-';
      // Pulse the topbar live indicator on every successful poll so the
      // operator can see the snapshot loop is actually breathing.
      const dot = document.getElementById('live-dot');
      if (dot) {
        dot.classList.remove('pulse', 'stale');
        dot.textContent = 'live';
        void dot.offsetWidth;
        dot.classList.add('pulse');
      }
      // Always, whatever pane is open: the firewall policy renderer carries
      // the commit-confirm, and the one-shot form prefills must land once.
      lastFWPolicy = snap.firewall_policy || null;
      renderFirewallPolicy(snap.firewall_policy);
      prefillWGInterface(snap.thresholds);
      renderSettings(snap.thresholds);
      lastWG = snap.wireguard || [];
      renderActive();
      if (isPaneActive('access') && (++pamTick % 5 === 0)) loadAccess();
    } catch (e) {
      console.error('refresh failed', e);
      // Say so instead of silently showing the last snapshot as if live.
      const dot = document.getElementById('live-dot');
      if (dot) { dot.classList.add('stale'); dot.textContent = 'offline'; }
    } finally {
      refreshing = false;
    }
  }
  function poll() {
    if (document.hidden) return;
    refresh();
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

  // Live-update text filters without re-fetching.
  document.getElementById('flow-filter').addEventListener('input', renderActive);
  document.getElementById('alert-filter').addEventListener('input', renderActive);

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
    if (el) el.addEventListener('change', renderActive);
  });

  document.getElementById('logout').addEventListener('click', async () => {
    const res = await fetch('/api/logout', { method: 'POST' });
    // A session from the identity provider is ended there as well.
    let next = '/login';
    if (res.status === 200) { try { next = (await res.json()).logout_url || next; } catch { /* stay local */ } }
    window.location.href = next;
  });

  wgCombo.init();
  {
    const npSel = document.getElementById('wg-np-select');
    if (npSel) npSel.addEventListener('change', showSelectedNetplan);
  }
  refresh();
  setInterval(poll, 2000);
  loadMe();
})();
