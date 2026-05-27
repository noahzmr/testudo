# Testudo - Device-Level Network Diagnostics Assessment

**Reviewer perspective:** senior network engineer / SRE / systems diagnostician
**Scope:** device-level troubleshooting, network quality measurement, local network diagnostics
**Codebase state at review:** 95 Go files, ~23K LOC, Go 1.25.6, `main` @ `9a42110`
**Verdict in one line:** This is a *real, working* observability tool - not vaporware - with genuinely good Linux-native collectors. Its biggest liabilities are **no IPv6**, **no automated tests**, **no L3 state introspection (ARP/neighbor/conntrack)**, and a **plain-HTTP web plane**.

---

## 0. Reality check: what actually exists

Contrary to how aspirational the `CLAUDE.md` reads, the code is substantially implemented and uses correct Linux mechanisms throughout. No mock/simulated data was found in the collectors or probes.

| Subsystem                           | Mechanism                                                                 | Real?    |
| ----------------------------------- | ------------------------------------------------------------------------- | -------- |
| ICMP / latency / loss               | `golang.org/x/net/icmp` raw socket, UDP-ICMP fallback                     | ✅        |
| DNS quality (system + per-resolver) | `net.Resolver`, direct nameserver queries                                 | ✅        |
| Traceroute                          | TTL-walk + ICMP TimeExceeded reader                                       | ✅        |
| Wi-Fi                               | nl80211 via `mdlayher/wifi` (genetlink) → `iw` → `/proc/net/wireless`     | ✅        |
| Bufferbloat                         | idle-vs-loaded RTT under HTTP saturation                                  | ✅        |
| TLS cert expiry                     | TLS handshake, leaf `NotAfter`                                            | ✅        |
| HTTP endpoint                       | `httptrace` phase timings (TCP/TLS/TTFB)                                  | ✅        |
| Interface health / stats            | `vishvananda/netlink` + `/proc/net/dev`                                   | ✅        |
| L2 (multicast rate, ARP churn)      | netlink counters + `/proc/net/arp` parse                                  | ✅        |
| Packet capture                      | `gopacket` AF_PACKET per-iface, ring buffer, pcap rotation, `tcpdump` mgr | ✅        |
| Flow aggregation                    | in-mem bidirectional 5-tuple table, LRU evict @4096                       | ✅        |
| Discovery                           | AF_PACKET ARP sweep, ICMP sweep, mDNS, LLDP, hand-rolled SNMPv2c          | ✅        |
| Firewall                            | `google/nftables` read/write + `iptables -L` parse (read)                 | ✅ (IPv4) |
| NAT (DNAT only)                     | nftables PREROUTING                                                       | ✅ (IPv4) |
| Routing                             | netlink read/write                                                        | ✅        |
| IPFIX export                        | hand-rolled RFC 7011                                                      | ✅        |
| Storage                             | SQLite (modernc, pure-Go) + downsampling                                  | ✅        |

**The honest gaps that recur everywhere:** IPv6, L3 neighbor/conntrack/policy-route introspection, link-layer PHY detail (speed/duplex/autoneg), systemd-resolved awareness, and tests.

---

# Part 1 - Device-Level Troubleshooting Capability Matrix

Legend: **Full** / **Partial** / **None**. "Mechanism" = how it's actually done in the code.

| #   | Capability                | Status      | Mechanism (as implemented)                                                                         | Gap / fix                                                                                                           |
| --- | ------------------------- | ----------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1   | Interface diagnostics     | **Full**    | `netops/iface.go` netlink LinkList/AddrList, MTU, flags, OperState, stats                          | No speed/duplex/autoneg (needs ethtool/`ETHTOOL_GLINKSETTINGS` via genetlink)                                       |
| 2   | Link state monitoring     | **Full**    | `iface_health.go` polls link up/running + transition alerts                                        | Polling not event-driven; subscribe to RTNETLINK `RTM_NEWLINK` for instant detection                                |
| 3   | IP config validation      | **Partial** | reads addrs/CIDR; can set static                                                                   | No "is this addr a duplicate / does it conflict / is RA-assigned" logic                                             |
| 4   | DNS troubleshooting       | **Full**    | system resolver + per-nameserver direct probes (`internal_dns.go`), DNS-failure burst detector     | No DNSSEC/DoT/DoH probing; no NXDOMAIN-hijack/captive detection                                                     |
| 5   | DHCP diagnostics          | **Partial** | `dhcp.go` execs dhclient/dhcpcd, detects mode via **lease-file existence**                         | Cannot read lease (server IP, expiry, offered GW/DNS); Debian paths hardcoded; no DHCPv6; no rogue-server detection |
| 6   | Gateway reachability      | **Full**    | ICMP collector + default-route enumeration                                                         | -                                                                                                                   |
| 7   | Routing analysis          | **Partial** | `route.go` netlink read/write all tables                                                           | No policy routing (`ip rule`/fwmark), no ECMP, no reachability validation pre-add                                   |
| 8   | MTU issues                | **Partial** | reads/sets interface MTU                                                                           | No **PMTU discovery** probe (DF-bit binary search), no ICMP-frag-needed-blocked detection                           |
| 9   | ARP/NDP inspection        | **Partial** | `l2.go` parses `/proc/net/arp` for churn; ARP sweep populates cache                                | No NDP (IPv6 neighbor), no netlink NEIGH dump, no stale/incomplete/duplicate-IP analysis                            |
| 10  | Packet loss detection     | **Full**    | ICMP timeout → `KindPacketLoss`; windowed `PacketLossDetector`                                     | -                                                                                                                   |
| 11  | Latency measurement       | **Full**    | ICMP RTT; min/max/avg/p95 in `metrics.go`                                                          | -                                                                                                                   |
| 12  | Jitter analysis           | **Full**    | mean-absolute-deviation `jitterMs()` + `JitterSpikeDetector`                                       | RFC 3550 IPDV would be more standard but MAD is fine                                                                |
| 13  | Throughput / bandwidth    | **Full**    | HTTP GET throughput probe; per-iface RX/TX rate ring buffer                                        | Single-stream HTTP only; no UDP/iperf-style, no upload test, no parallel streams                                    |
| 14  | TCP vs UDP behavior       | **Partial** | separate TCP-connect & UDP probes; `/proc/net/snmp` retrans detector                               | No per-flow RTT/RTX from kernel (`ss -ti` / `tcp_info`), no UDP loss accounting                                     |
| 15  | Wi-Fi quality             | **Full**    | nl80211 signal/bitrate/noise/beacon-loss/retries with `iw`+proc fallback                           | IPv4-thinking elsewhere doesn't affect this; solid                                                                  |
| 16  | Signal strength           | **Full**    | dBm via nl80211 station info                                                                       | -                                                                                                                   |
| 17  | Connection stability      | **Full**    | link transitions, wifi disassoc, anomaly cooldowns                                                 | -                                                                                                                   |
| 18  | Firewall debugging        | **Partial** | nft + iptables enumeration, chain-level counters                                                   | **No per-rule hit counters**, no policy display, no rule decode, no log target                                      |
| 19  | VPN diagnostics           | **Partial** | tun/wg ifaces enumerated; OperUnknown treated as up                                                | No tunnel-liveness (peer reachable?), no wg handshake age, no per-iface DNS                                         |
| 20  | NAT behavior              | **Partial** | DNAT rules add/read; NAT-exhaustion via conntrack count                                            | **No conntrack table inspection** (can't see/flush live NAT'd flows); no SNAT/masquerade mgmt                       |
| 21  | TLS/SSL verification      | **Full**    | handshake + expiry; HTTP endpoint TLS timing                                                       | No chain/cipher/protocol-version audit                                                                              |
| 22  | Socket/connectivity test  | **Full**    | TCP-connect, UDP, DNS, HTTP probes (on-demand via `probe` cmd)                                     | -                                                                                                                   |
| 23  | Service reachability      | **Full**    | top-talkers TCP-connect to service port; port scan                                                 | -                                                                                                                   |
| 24  | IPv4/IPv6 dual-stack      | **None**    | **ICMP hardcoded `ip4:icmp`; filter/NAT IPv4-only; capture decode TCP/UDP-only (skips ICMPv6/ND)** | Largest single gap - see §1a                                                                                        |
| 25  | Time sync (NTP)           | **None**    | UDP/123 in scan port list but never probed; no chrony/ntpd offset read                             | Add NTP client probe + `chronyc tracking`/`ntpq` parse                                                              |
| 26  | Interface statistics      | **Full**    | netlink Statistics (rx/tx bytes/pkts/errors/dropped/collisions/multicast)                          | Snapshot only; rate/delta done only for bandwidth                                                                   |
| 27  | Packet capture            | **Full**    | gopacket AF_PACKET, ring buffer, selective pcap, tcpdump                                           | No BPF filter at gopacket capture time (full decode of all pkts)                                                    |
| 28  | Deep protocol inspection  | **Partial** | L3/L4 extraction only; LLDP/SNMP/mDNS hand-decoded                                                 | No DPI/app-layer classification beyond port→service map                                                             |
| 29  | Network event logging     | **Full**    | event bus → SQLite samples/anomalies/incidents; pcap bundles on CRITICAL                           | -                                                                                                                   |
| 30  | Historical trend analysis | **Full**    | SQLite time-series, downsample >24h to 5-min buckets, 30-day retention, replay engine              | Flows table is cumulative-not-timebucketed; no per-snapshot flow history                                            |

## §1a - The IPv6 problem (cross-cutting, high severity)

IPv6 is effectively absent from the data path:
- ICMP/ping/traceroute: hardcoded `ip4:icmp` - no `ipv6-icmp`/ICMPv6.
- `netops/filter.go` and `netops/nat.go`: explicit `TableFamilyIPv4` guards; v6 traffic never matched.
- `capture/capture.go` `decode()`: extracts only IPv4 + TCP/UDP; **drops ICMPv6, NDP, DHCPv6, RA**.
- No router-advertisement / SLAAC / DAD / NDP visibility at all.

On any modern dual-stack network, Testudo is **blind to half the stack**. This is the #1 correctness gap. Fix requires: ICMPv6 probe path, `AF_INET6` in filter/NAT, a v6 branch in capture decode, and NDP via netlink NEIGH (`AF_INET6`).

---

# Part 2 - Network Quality Evaluation

## What's already measured (and how well)

| Metric                      | Continuous vs sampled              | Where                   | Quality                             |
| --------------------------- | ---------------------------------- | ----------------------- | ----------------------------------- |
| Latency (min/max/avg/p95)   | continuous, 256-sample rolling     | `metrics.go`            | Good. Add p50/p99.                  |
| Jitter                      | continuous (MAD)                   | `metrics.go`            | Good.                               |
| Packet loss                 | continuous, windowed               | `metrics.go` + analyzer | Good.                               |
| DNS response quality        | continuous per-name + per-resolver | collectors              | Good.                               |
| Wi-Fi signal/bitrate/beacon | sampled 5–10s                      | `wifi.go`               | Good.                               |
| Bufferbloat                 | sampled (hours, opt-in, invasive)  | `bufferbloat.go`        | Correct cadence.                    |
| Bandwidth RX/TX             | continuous 1s rate ring            | `bandwidth.go`          | Good.                               |
| Congestion / retrans        | continuous via `/proc/net/snmp`    | analyzers               | Coarse (system-wide, not per-flow). |
| Stability over time         | continuous (transitions + SQLite)  | engine                  | Good.                               |

## What's missing for a real "network quality score"

1. **No composite quality score.** There is no MOS-style or weighted index combining loss/latency/jitter into a single grade per target/link. There IS a `tui/grade.go` and `web/grade.go` - confirm whether that's a real scoring model or a display helper; if display-only, build a proper scorer.
2. **No baseline/anomaly-relative scoring beyond spike factors.** `LatencySpikeDetector` uses 3× rolling mean - good - but there's no persisted *baseline profile* per target (per-hour-of-day, per-link) to compare "is tonight worse than normal."
3. **No bufferbloat grade letter (A–F)** despite measuring the delta - currently just severity buckets.
4. **No ISP-degradation isolation** (first-hop vs gateway vs WAN vs target decomposition into a single "where's the problem" verdict).
5. **Per-flow TCP quality** (RTX rate, RTT, cwnd) from `tcp_info`/`ss -ti` is absent - this is the single highest-value passive quality signal on a busy host.

## Recommendations - metrics policy

**Collect continuously (cheap):** link state, iface counters/rates, ARP churn, wifi signal, system retrans counters, flow byte counts, gateway+resolver RTT (low pps).
**Sample (expensive/invasive):** bufferbloat (hours, opt-in), throughput (on-demand or hourly), traceroute (15min–1h), full LAN reachability sweep (60s+), TLS expiry (daily).

**Degraded thresholds (sane defaults, all already configurable):**

| Metric        | Healthy | Degraded   | Bad     |
| ------------- | ------- | ---------- | ------- |
| Loss          | <0.5%   | 0.5–2%     | >2%     |
| RTT (gateway) | <5ms    | 5–30ms     | >30ms   |
| RTT (WAN)     | <50ms   | 50–150ms   | >150ms  |
| Jitter        | <5ms    | 5–20ms     | >20ms   |
| DNS           | <50ms   | 50–120ms   | >120ms  |
| Bufferbloat Δ | <30ms   | 30–100ms   | >100ms  |
| Wi-Fi signal  | >-60dBm | -60 to -75 | <-75dBm |

**Storage / telemetry architecture (current is mostly right):**
- Keep the event-bus → metrics-aggregator → SQLite pipeline.
- Add a **rollup table keyed (target, hour-bucket)** holding p50/p95/p99/loss/jitter for baseline comparison and long-horizon trends - separate from raw samples so retention can differ.
- Persist a **periodic flow snapshot with timestamp** (current `flows` table is cumulative; you lose the time dimension for "what was talking at 02:00").
- Add **incident table cap / rotation** - currently unbounded.

---

# Part 3 - Local Network Troubleshooting

## Implemented, real

| Capability         | How                                                                      | Notes                                            |
| ------------------ | ------------------------------------------------------------------------ | ------------------------------------------------ |
| Device discovery   | ARP sweep (AF_PACKET raw), ICMP sweep, mDNS PTR, passive `/proc/net/arp` | ARP-first is the correct design choice           |
| ARP scanning       | hand-built 42-byte frames, `/20` cap, per-host 1ms stagger               | Solid                                            |
| mDNS/Bonjour       | UDP 224.0.0.251:5353 `_services._dns-sd._udp.local` PTR                  | Probe only; no full service enumeration          |
| LLDP               | passive AF_PACKET 0x88cc, full TLV 0–8 decode, 802.1Q aware              | Excellent; switch/AP/router classification       |
| SNMP               | hand-rolled SNMPv2c GET (sysDescr/Name/UpTime/ifNumber)                  | No vendor-MIB sysObjectID classification         |
| Port reachability  | TCP-connect (64 workers) + UDP one-byte (32 workers)                     | Connect scan, not raw SYN - fine, less privilege |
| MAC vendor         | hardcoded 256-entry OUI map                                              | ~25k official OUIs missing; ship IEEE OUI file   |
| Subnet analysis    | derived from iface CIDRs for sweeps                                      | -                                                |
| Topology inference | passive from flows + LLDP neighbors                                      | -                                                |
| Flow/east-west     | bidirectional aggregator, LAN matrix, process correlation                | proc match via `/proc/net/tcp` + `/proc/*/fd`    |

## Missing for a "complete LAN troubleshooting platform"

| Capability                      | Status                           | How to implement                                                             | Privilege        | Risk               |
| ------------------------------- | -------------------------------- | ---------------------------------------------------------------------------- | ---------------- | ------------------ |
| **Rogue DHCP detection**        | None                             | Broadcast DHCPDISCOVER, collect *all* DHCPOFFERs, flag >1 server             | CAP_NET_RAW      | Active probe noise |
| **Duplicate IP detection**      | None                             | ARP-probe (RFC 5227): see if >1 MAC answers for an IP; cross-check ARP churn | CAP_NET_RAW      | Low                |
| **SSDP/UPnP**                   | None (port listed, never probed) | M-SEARCH to 239.255.255.250:1900, parse `LOCATION`                           | none             | Low                |
| **VLAN visibility**             | Partial (LLDP caps only)         | Parse 802.1Q tags in capture decode; per-VLAN flow accounting                | CAP_NET_RAW      | Low                |
| **Switch diagnostics**          | None                             | SNMP bridge-MIB / dot1d, STP state                                           | community string | Read-only safe     |
| **Captive portal detect**       | None                             | HTTP probe to known generate_204 URL, detect 302/content mismatch            | none             | Low                |
| **Broadcast/multicast inspect** | Partial (rate only)              | Decode IGMP/SSDP/mDNS/LLMNR in capture                                       | CAP_NET_RAW      | Low                |
| **NetBIOS/WINS**                | None                             | UDP 137 name query                                                           | none             | Low                |
| **Asymmetric routing**          | None                             | Compare RX iface vs route-predicted TX iface per flow                        | netlink read     | Low                |
| **Cable/link negotiation**      | None                             | ethtool genetlink: speed/duplex/autoneg/link-detected                        | CAP_NET_ADMIN    | Read-only safe     |
| **Wi-Fi interference**          | Partial                          | nl80211 survey dump (channel busy time, noise)                               | CAP_NET_ADMIN    | Read-only          |

**Cross-platform note:** Everything here is Linux-specific (AF_PACKET, netlink, nl80211, `/proc`). macOS/BSD/Windows would need `bpf(4)`/`route(4)`/WinPcap-equivalents - currently no abstraction seam for that, and the docs scope it to Linux, which is fine.

---

# Part 4 - Troubleshooting Workflows

These map directly onto existing primitives. Where a step needs something not yet built, it's flagged `[GAP]`.

### "No internet connection"
1. Link up? (`iface_health`) → if down: PHY/cable `[GAP: ethtool link-detected]`.
2. Have IP? (`iface.go` addrs) → if none: DHCP path - is dhclient bound, lease present? `[GAP: lease introspection]`.
3. Default route exists? (`route.go`).
4. Gateway pingable? (ICMP). → fail = L2/local issue.
5. DNS resolves? (`dns.go`/`internal_dns.go`).
6. WAN target pingable by IP? (ICMP) vs by name → isolates DNS vs routing.
**Verdict logic:** first failing layer = root cause. **Automate** as a `testudo doctor` command chaining these.

### "Slow internet"
1. Throughput probe (have it) vs link capacity.
2. Bufferbloat run (have it) → queue latency under load.
3. Per-flow top-talkers (have it) → is a local host saturating?
4. Wi-Fi signal/bitrate (have it) → PHY-rate capped?
5. WAN RTT/loss trend vs baseline `[GAP: baseline profile]`.

### "Intermittent connectivity"
1. Continuous gateway+WAN ICMP loss windows (have it).
2. Link transition log (have it).
3. Wi-Fi disassoc/beacon-loss events (have it).
4. ARP churn / duplicate IP `[GAP: dup-IP probe]` → flapping MAC = rogue device / IP conflict.

### "DNS works slowly"
1. Per-resolver direct latency (`internal_dns.go`) - isolates stub vs upstream.
2. DNS burst/failure detector (have it).
3. Compare resolvers `[partial: have per-resolver, add ranking]`.

### "Only some services work"
1. Per-port TCP-connect probe (have it).
2. Firewall rule enumeration (have it) - `[GAP: per-rule counters]` to see which rule drops.
3. NAT/DNAT rule check (have it).

### "VPN connected but unreachable"
1. tun/wg iface up + has addr (have it).
2. Route over tunnel present? (`route.go`).
3. Ping tunnel remote endpoint `[GAP: wg handshake-age read]`.
4. DNS over tunnel? `[GAP: per-iface DNS]`.

### "Wi-Fi unstable"
1. Signal/noise/SNR trend + beacon loss + retries (all have it).
2. Disassoc events (have it).
3. `[GAP: nl80211 survey]` channel-busy / interference.

### "High latency spikes"
1. `LatencySpikeDetector` (3× baseline) (have it).
2. Bufferbloat correlation (have it).
3. Per-hop traceroute deltas (have it) → which hop introduces it.

### "Local devices unreachable"
1. ARP sweep / reachability (have it).
2. Same subnet? netmask check (have it).
3. ARP resolves? churn/dup `[GAP: dup-IP]`.

### "Packet loss during gaming/VoIP"
1. Continuous loss + jitter to target (have it).
2. Bufferbloat (have it) - usually the culprit.
3. Per-flow QoS `[GAP: no DSCP/queue inspection]`.

### "IPv6 broken but IPv4 works"
**`[GAP - entirely unsupported]`.** Requires the §1a IPv6 work: ICMPv6 ping, RA/NDP visibility, v6 route check, DHCPv6/SLAAC state.

### "MTU / path fragmentation"
**`[GAP]`** - needs a DF-bit PMTU discovery probe (binary search packet size with DF set, watch for frag-needed). Not implemented; interface MTU read only.

**Automation opportunity:** ship a single `testudo doctor [target]` that runs the "No internet" + "Slow" chains and prints a layered PASS/FAIL with the first failing layer highlighted. Highest-leverage UX win.

---

# Part 5 - Architecture & Engineering Review

## What's good

- **Event-driven control plane** (`events.Bus`, 2048-buffer, uint64 bitmask subscriber filtering) with a **deliberate, documented bypass**: packet→flow data writes directly to the aggregator instead of fanning out per-packet on the bus. This is the *correct* performance call and shows real engineering judgment.
- **Clean goroutine lifecycle**: central `sync.WaitGroup`, `ctx.Done()` propagation, `Stop()` drains workers. ~17 long-lived goroutines, all accounted for.
- **Pure-Go portability**: modernc SQLite (no cgo), gopacket AF_PACKET (no libpcap link), hand-rolled SNMP/IPFIX (no dep bloat).
- **Capability-based privilege**: runs unprivileged with `cap_net_raw,cap_net_admin=+ep`; soft-fails per-interface when caps missing rather than crashing; `--allow-netops-write` gate for mutations.
- **Sensible storage**: SQLite with indices, downsampling (>24h → 5-min buckets, 30-day retention), incident pcap bundles.

## Weaknesses (ranked)

| #   | Weakness                                     | Severity     | Detail                                                                                                                                                        |
| --- | -------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Zero automated tests**                     | **Critical** | No `*_test.go` in production code. 23K LOC of socket/netlink/parsing logic with no regression safety net.                                                     |
| 2   | **No IPv6 in data path**                     | **Critical** | See §1a. Functional-correctness gap on modern networks.                                                                                                       |
| 3   | **Web plane is plain HTTP**                  | High         | bcrypt + HttpOnly/SameSite cookies, but no TLS and **no CSRF token** on login POST. LAN-only safe; unsafe remote without a reverse proxy.                     |
| 4   | **Monolithic process**                       | High         | All collectors/analyzers/web in one PID with elevated caps. One panic can take the whole engine down; large attack surface holding CAP_NET_ADMIN. No seccomp. |
| 5   | **No L3 state introspection**                | High         | No netlink NEIGH (ARP/NDP) dump, no conntrack table read, no policy routing - blinds NAT/duplicate-IP/asymmetric-route troubleshooting.                       |
| 6   | **Unbounded tables**                         | Medium       | `flows` is cumulative (loses time dimension); `incidents` has no hard cap.                                                                                    |
| 7   | **Polling where netlink could push**         | Medium       | Link/route/addr changes polled instead of subscribing to RTNETLINK multicast groups - slower detection, wasted ticks.                                         |
| 8   | **systemd-resolved unhandled**               | Medium       | `dns.go` rewrites `/etc/resolv.conf` which is a read-only stub symlink on most modern distros → silent failure. No `resolvectl` path.                         |
| 9   | **No config validation / no env-var config** | Low          | Flags + JSON settings, no range validation; fine for a CLI but brittle.                                                                                       |
| 10  | **Manual bus unsubscribe**                   | Low          | Subscriber `Close()` is caller responsibility; forgotten close → blocked publish.                                                                             |

## Recommended technical additions

- **eBPF opportunities** (biggest long-term lever):
  - `tcp_info` / `sock_ops` or just `ss -ti` parsing for per-flow RTT/RTX/cwnd - far richer than `/proc/net/snmp` aggregates.
  - XDP/tc for high-rate flow accounting without per-packet userspace cost (you already avoid the bus for this reason; eBPF is the natural next step).
  - `kprobe`/tracepoint on `icmp_send`/`fib` for drop-reason and frag-needed events.
- **Netlink push, not poll**: subscribe to `RTNLGRP_LINK`, `RTNLGRP_IPV4_ROUTE`, `RTNLGRP_NEIGH`, `RTNLGRP_IPV4_IFADDR` for instant change events (already importing `vishvananda/netlink` + `mdlayher/netlink`).
- **conntrack** via `mdlayher/netlink` to `nf_conntrack` (NFNL) - live NAT flow table, not just the count.
- **ethtool** via genetlink (`mdlayher/genetlink` already a dep) for speed/duplex/autoneg/link-detected.
- **nl80211 survey** dump (via existing `mdlayher/wifi`/genetlink) for channel-busy/interference.
- **Per-rule nftables counters**: add `expr.Counter` to rules and read handles - turns firewall view from "chain totals" into "which rule fired."

## Production-readiness verdict

| Dimension               | Rating                                                                        | Note                                                     |
| ----------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------- |
| Functional breadth      | **Strong**                                                                    | Genuinely broad, genuinely real.                         |
| Correctness (IPv4)      | **Good**                                                                      | Sound socket/netlink semantics.                          |
| Correctness (IPv6)      | **Failing**                                                                   | Absent.                                                  |
| Reliability             | **Medium**                                                                    | No tests; monolithic blast radius.                       |
| Security                | **Medium-Low**                                                                | HTTP web plane, no CSRF, broad caps, no seccomp.         |
| Scalability             | **Good for host/LAN**                                                         | In-mem bounded structures; not multi-node.               |
| Observability of itself | **Medium**                                                                    | Soft-fails silently; add a "degraded subsystems" status. |
| **Overall**             | **Capable lab/LAN tool; not yet production for untrusted/remote/dual-stack.** |                                                          |

---

# Prioritized Roadmap

### Immediate wins (days, high value/low effort)
1. **`testudo doctor`** command chaining the Part-4 "no internet"/"slow" workflows into a layered PASS/FAIL - turns existing primitives into a product feature.
2. **TLS for the web plane + CSRF token** on login; or document the reverse-proxy requirement prominently.
3. **Per-rule nftables counters** (add `expr.Counter`) - small change, big firewall-debug payoff.
4. **systemd-resolved detection** in `dns.go`: detect stub symlink, fall back to `resolvectl`.
5. **SSDP M-SEARCH + captive-portal probe** - port already in the list; trivial additions.
6. **Ship the IEEE OUI database** instead of 256 hardcoded prefixes.

### Short term (weeks)
7. **Test suite**: start with parsers (`/proc/net/arp`, `/proc/net/snmp`, iptables output, SNMP/LLDP/IPFIX TLV codecs) - pure functions, easy wins, highest regression risk.
8. **L3 state introspection**: netlink NEIGH dump (ARP/NDP), duplicate-IP (RFC 5227) probe, conntrack table read.
9. **ethtool link detail** (speed/duplex/autoneg) + **PMTU discovery probe**.
10. **Netlink event subscription** for link/route/addr/neigh (replace polling).
11. **Baseline/rollup table** (target × hour bucket) + a real quality score.

### Long term (months)
12. **IPv6 across the data path** (§1a) - ICMPv6 probes, v6 filter/NAT, capture decode v6 + NDP/RA visibility.
13. **eBPF telemetry** (`tcp_info` per-flow, XDP flow accounting, drop-reason tracepoints).
14. **Privilege separation**: split the CAP_NET_ADMIN-holding capture/netops into a thin helper; run web/TUI unprivileged; add seccomp profile.
15. **Time-bucketed flow history** + incident table rotation.

---

## Security concerns (summary)
- Plain-HTTP web plane + no CSRF: credential/session theft on shared LAN; fix with TLS + CSRF or mandate reverse proxy.
- Monolithic process holds CAP_NET_RAW + CAP_NET_ADMIN: large privileged attack surface, no seccomp.
- nftables/route/NAT mutation gated only by a single `--allow-netops-write` bool; no per-op authz or audit log of changes.
- Active discovery (ARP/ICMP/port sweeps) is intrusive - ensure it stays opt-in (it is) and rate-limited (it is, /20 cap + worker semaphores).

## Reliability concerns (summary)
- No tests → refactors are blind.
- One goroutine panic can crash the shared engine; add per-collector `recover()` + restart, and a self-status surface for soft-failed subsystems.
- Unbounded `incidents`/cumulative `flows` → long-run growth.
