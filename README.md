```text
      ___    __________ ________   ______ __________  __   __   _______     ______
 ,,  // \\   \__    __/ |  ____/  /  ___/ \__    __/ |  | |  | |   ___  \  /  __   \
(_,\/ \_/ \     |  |    |  |___   \  \       |  |    |  | |  | |  |   \  \ |  |  |  |
  \ \_/_\_/>    |  |    |   ___|   \  \      |  |    |  | |  | |  |   |  | |  |  |  |
  /_/  /_/      |  |    |  |_____  /  /      |  |    |  |_|  | |  |___/  / |  |__|  |
                |__|    |_______/ /__/       |__|     \_____/  |________/   \______/
```

<div align="center">

  <h1>Testudo</h1>

  <p>
    <strong>Your Linux network, in one quiet terminal.</strong>
    <br/>
    <em>A friendly, terminal-native home for everything happening on your box - flows, DNS, latency, firewall, routes, NAT, devices - all in one Go binary.</em>
  </p>

  <p>
    <a href="#quick-start"><strong>Quick Start »</strong></a>
    &nbsp;·&nbsp;
    <a href="#features">Features</a>
    &nbsp;·&nbsp;
    <a href="#tui--web-interface">Web UI</a>
    &nbsp;·&nbsp;
    <a href="#further-documentation">Docs</a>
    &nbsp;·&nbsp;
    <a href="https://github.com/noahzmr/testudo/issues/new" target="_blank"><strong>Report an issue »</strong></a>
  </p>

  <p>

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Linux](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Debian-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/License-MPL--2.0-FF7139?style=for-the-badge&logo=mozilla&logoColor=white)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-active-success?style=for-the-badge)](#)
[![Pure Go](https://img.shields.io/badge/cgo-free-2EA44F?style=for-the-badge&logo=go&logoColor=white)](#)

[![Bubble Tea](https://img.shields.io/badge/TUI-Bubble%20Tea-FF75B7?style=flat-square&logo=charm&logoColor=white)](https://github.com/charmbracelet/bubbletea)
[![Lip Gloss](https://img.shields.io/badge/Style-Lip%20Gloss-EC6CB9?style=flat-square)](https://github.com/charmbracelet/lipgloss)
[![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![gopacket](https://img.shields.io/badge/Capture-gopacket-1E90FF?style=flat-square)](https://github.com/google/gopacket)
[![netlink](https://img.shields.io/badge/Kernel-netlink-555555?style=flat-square&logo=linux&logoColor=white)](https://github.com/mdlayher/netlink)
[![AF_PACKET](https://img.shields.io/badge/Sockets-AF__PACKET-555555?style=flat-square&logo=linux&logoColor=white)](#)
[![iptables](https://img.shields.io/badge/Firewall-iptables%20%7C%20nftables-D22128?style=flat-square&logo=iptables&logoColor=white)](https://netfilter.org/)
[![IPFIX](https://img.shields.io/badge/Export-IPFIX-009688?style=flat-square)](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
[![opsanio](https://img.shields.io/badge/Integration-opsanio-1E2A38?style=flat-square)](https://autonubil.de/home#appliances)
[![LLDP](https://img.shields.io/badge/Discovery-LLDP-007ACC?style=flat-square)](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol)
[![SNMP](https://img.shields.io/badge/Discovery-SNMPv2c-005571?style=flat-square)](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
[![mDNS](https://img.shields.io/badge/Discovery-mDNS-7B68EE?style=flat-square)](https://en.wikipedia.org/wiki/Multicast_DNS)
[![ARP](https://img.shields.io/badge/Discovery-ARP-708090?style=flat-square)](#)
[![Sentry](https://img.shields.io/badge/Optional-Sentry-362D59?style=flat-square&logo=sentry&logoColor=white)](https://sentry.io/)
[![Guacamole](https://img.shields.io/badge/Optional-Apache%20Guacamole-D22128?style=flat-square&logo=apache&logoColor=white)](https://guacamole.apache.org/)

  </p>
</div>


Live flow analytics across every interface, replayable sessions, anomaly detection, firewall and routing control, NAT, network discovery, **IPFIX flow export to [opsanio](https://autonubil.de/home#appliances)**, and a unified web console - all driven by a single Bubble Tea TUI and mirrored to a small embedded HTTP UI. Whatever you need to look at, there's a tab for it.

- **Author**: Noah Zeumer &lt;[github.com/noahzmr](https://github.com/noahzmr)&gt;
- **License**: MPL-2.0 with branding restrictions (see [LICENSE](./LICENSE) and [NOTICE](./NOTICE))
- **Status**: active development, Linux-first (Ubuntu / Debian) - hello, come on in

---

## Why It Matters

If you've ever debugged a flaky network, you know the drill. One terminal for `tcpdump`, another for `iftop`, a third for `ss`, `nmap` in a fourth, `iptables` and `nft` in a fifth, `ip route` in a sixth, and somewhere off to the side a Grafana tab that doesn't quite line up with any of them. Each of those tools is great on its own. They just don't talk to each other - and the moment the problem stops, the evidence is gone.

Testudo is a gentler take on the same job. One place to look. One memory across time. Less ceremony.

- **One TUI instead of six terminals.** Every signal - flows, DNS, latency, firewall hits, route changes - lives in the same place.
- **"What was the network doing at 03:14?"** A session ID is enough. Open it in replay and scroll.
- **No always-on `tcpdump`.** PCAPs are captured only when something interesting actually happens, then rotated.
- **No external metrics stack.** Testudo keeps its own time-series in SQLite. One file. One binary. Done.
- **One engine, two faces.** The TUI and the web UI are the same thing over different transports - a feature in one shows up in the other for free.

Underneath: pure-Go netlink, AF_PACKET, and `/proc`. No `cgo`, no external broker, no external metrics backend. One binary, one config, one event bus - and you're off.

---

## What does "Testudo" mean?

**Testudo** is Latin for **tortoise** - and the word lives in *two* worlds that both describe this tool.

### 1. Biology - the tortoise genus

*Testudo* is the scientific genus name for the palearctic (European) land tortoises. The best-known species are *Testudo hermanni* (Hermann's tortoise) and *Testudo graeca* (the Greek tortoise).

> **The tortoise is slow** - and **slow is exactly the symptom this tool was built to diagnose.**
>
> The reason most operators reach for a packet analyzer in the first place is some variation of *"the network feels slow."* Latency creeping up. DNS taking just a bit too long. A flow that used to be 100 ms now sitting at 400 ms. A retransmission rate that no dashboard surfaces. Testudo is built for those questions: *where* is it slow, *when* did it start being slow, and *what* was the network doing the moment it got slow.

### 2. Military history - the Roman *Testudo* formation

In the legions, a *Testudo* was a tight tactical formation in which soldiers closed ranks and locked their shields together - overhead and on the flanks - to create a gap-free shell that absorbed arrow volleys and falling stones.

That formation maps almost one-to-one onto how Testudo is built:

- **Shell** => a hardened observation layer around the host networking stack.
- **Formation** => many small subsystems (collectors, analyzers, engines) interlocking through one event bus - no single subsystem is exposed alone.
- **Coverage without gaps** => every observable signal (flow, DNS, ICMP, ARP, LLDP, SNMP, firewall, route, NAT) is captured by *some* shield; nothing falls through.
- **Endurance** => low-overhead, replayable, made to run quietly on a box for weeks.

### Mascot

A turtle peeking out from under its shell - half forensic, half cozy. The terminal-native identity is intentional: this is a tool you live inside, not one you click through.

---

## Table of Contents

- [Why It Matters](#why-it-matters)
- [What does "Testudo" mean?](#what-does-testudo-mean)
- [Features](#features)
- [TUI & Web Interface](#tui--web-interface)
- [Architecture](#architecture)
- [System Design Philosophy](#system-design-philosophy)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Instructions](#build-instructions)
- [CLI Reference & Options](#cli-reference--options)
- [Configuration System](#configuration-system)
- [Network Quality Grade](#network-quality-grade)
- [Directory Structure](#directory-structure)
- [Development Guide](#development-guide)
- [Further Documentation](#further-documentation)
- [Glossary - Networking Terms for Beginners](#glossary---networking-terms-for-beginners)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Branding](#branding)
- [Acknowledgments](#acknowledgments)

---

## Features

### Live Observability

- **ICMP latency, RTT, jitter, packet loss** - per target, with rolling 20-sample statistics.
- **DNS resolver health probing** - per-name latency and failure-rate tracking.
- **Multi-interface AF_PACKET capture** - physical, wireless, VLAN, bridge, tunnel, VPN, container, and virtual interfaces (`eth0`, `wlan0`, `tun0`, `wg0`, `docker0`, `br0`, …).
- **Process-to-flow correlation** - via `/proc/net/*` and `/proc/<pid>/fd` - every flow is tagged with the process that owns it.
- **DNS reverse correlation** - flows are annotated with the name that originally resolved to the far end.
- **Service catalog** - well-known ports mapped to protocol names (HTTP, HTTPS, SSH, DNS, NTP, MySQL, PostgreSQL, Redis, and more).
- **Interface throughput accounting** - RX and TX per direction, per interface.

### Flow Engine

The flow engine aggregates packets into intelligent flow summaries rather than persisting raw packets, and enriches each flow with process ownership, DNS resolution, service classification, and NAT/firewall state.

```text
┌ Live Flows ─────────────────────────────────────────┐
│ IFACE    PROCESS   SRC               DST           │
│ eth0     firefox   192.168.1.20      youtube.com   │
│ wg0      ssh       10.0.0.10         10.0.0.1      │
│ docker0  redis     172.18.0.2        172.18.0.5    │
└─────────────────────────────────────────────────────┘
```

Tracked per flow: source/destination, ports, protocol, throughput, retransmissions, packet loss, ingress interface, egress interface, process ownership, NAT state, firewall state.

### Network Discovery

Testudo runs **layered discovery** - passive listeners are always on when discovery is enabled; active probes are opt-in. The goal is "find every reachable device on every connected subnet, even the ones that drop ICMP."

```text
┌ Devices ─────────────────────────────────────────────────────────────┐
│ HOSTNAME       IP             TYPE       SOURCE        STATUS        │
│ router.local   192.168.1.1    Router     lldp+snmp     Active        │
│ sw-core-01     192.168.1.2    Switch     lldp          Active        │
│ ap-floor3      192.168.1.5    AP         lldp          Active        │
│ nas01          192.168.1.10   NAS        snmp          Active        │
│ printer01      192.168.1.40   Printer    arp-sweep     Idle          │
│ ?              192.168.1.77   Unknown    arp-sweep     Active        │
└──────────────────────────────────────────────────────────────────────┘
```

Each device is tracked with IP, MAC, hostname, vendor (via embedded OUI table), interface, source, device type, first/last-seen timestamps, and - for managed gear - system name, description, object ID, contact, location, uptime, interface count, LLDP chassis/port IDs and capabilities.

**Discovery layers (latest optimization pass):**

| Layer         | Mode       | What it does                                                                                                                           | Cost     |
| ------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| ARP cache     | Passive    | Reads `/proc/net/arp` every tick - zero traffic.                                                                                       | None     |
| Flow observe  | Passive    | Every new flow contributes endpoint visibility.                                                                                        | None     |
| LLDP listen   | Passive    | AF_PACKET listener on ethertype `0x88cc` - neighbours announce themselves; ideal for switches/APs/phones.                              | None     |
| **ARP sweep** | **Active** | **Broadcast ARP for every host in every connected /22 - catches ping-shy devices that ICMP misses.**                                   | One-shot |
| ICMP sweep    | Active     | Echo to each host in the local subnets (capped by `--max-subnet-bits`).                                                                | One-shot |
| **SNMPv2c**   | **Active** | **Hand-rolled BER GET on UDP/161 - pulls `sysName`, `sysDescr`, `sysObjectID`, `sysContact`, `sysLocation`, `sysUpTime`, `ifNumber`.** | Bounded  |
| mDNS query    | Active     | One-shot `_services._dns-sd._udp.local` query for service-advertising hosts.                                                           | One-shot |
| TCP/UDP probe | Active     | Targeted port probes - service hints (HTTP, SSH, SMB, …).                                                                              | Targeted |
| NetBIOS       | Active     | NetBIOS name-service query for legacy Windows hosts.                                                                                   | Targeted |

**Why this layout matters:**

- **ARP sweep is the single biggest coverage win.** ICMP echo is dropped by a long tail of consumer devices (Windows firewall defaults, IoT silence, "ping-shy" servers); ARP, by contrast, *has to* answer for the host to be reachable on the LAN. The ARP sweep is parallelized across interfaces and capped at `/20` (4096 hosts) so a misconfigured `/16` doesn't generate 64k frames in one tick.
- **LLDP gives free identification.** When a directly-connected switch or AP speaks LLDP, you get its chassis ID, port description, system name, system description and capabilities - without sending a single packet.
- **SNMPv2c reaches managed gear that doesn't speak LLDP.** The probe is hand-rolled (~250 lines, no external dependency) and runs with **bounded concurrency** plus a per-host timeout (default 1 s) so SNMP-dark hosts don't stall the sweep.
- **Subnet expansion is capped.** `MaxSubnetBits = 10` (default) gives `/22 = 1024 hosts`. Set to `8` for strict `/24` behaviour, or `12` for `/20`. Anything wider is silently skipped to avoid burying the local NIC.
- **Per-interface goroutine isolation.** Each interface gets its own listener goroutine; a stuck or erroring interface can't starve the others.

### Interface Management

Interfaces can be enabled, disabled, switched to DHCP, assigned static IPs, gateways, and DNS servers - directly from the TUI or web UI.

```text
┌ Interfaces ─────────────────────────────┐
│ eth0                                    │
│ Status:  UP                             │
│ Mode:    DHCP                           │
│ IPv4:    192.168.1.20/24                │
│ Gateway: 192.168.1.1                    │
│ RX: 122 MB/s     TX: 12 MB/s            │
└─────────────────────────────────────────┘
```

### Firewall Management

Current backend: `iptables` / `nftables`. `firewalld` support is on the roadmap.

Supported operations: inspect rules, inspect counters, inspect blocked traffic, hit counts, create rules, remove rules, replay firewall events.

```text
┌ Firewall Rules ─────────────────────────────────────┐
│ Chain: INPUT                                        │
│ DROP tcp -- 0.0.0.0/0 -> 22/tcp                     │
│ Hits: 1221                                          │
│ Blocked Traffic: 82 MB                              │
└─────────────────────────────────────────────────────┘
```

### Routing Management

Inspect routing tables, add static routes, remove routes, and replay route changes from the historical log.

```text
┌ Static Routes ──────────────────────────────────────┐
│ 10.0.0.0/24    via 192.168.1.1   dev eth0          │
│ 172.16.0.0/16  via 10.0.0.1      dev tun0          │
└─────────────────────────────────────────────────────┘
```

### NAT & Port Forwarding

Create and remove port forwards, inspect NAT and masquerading rules, and observe forwarding counters.

```text
┌ NAT Rules ──────────────────────────────────────────┐
│ DNAT tcp 0.0.0.0:443 -> 192.168.1.10:443           │
│ Hits: 8421                                          │
│ Forwarded: 12.4 GB                                  │
└─────────────────────────────────────────────────────┘
```

### Anomaly Detection & Alerting

A continuous analysis engine watches latency, jitter, packet loss, DNS timing, retransmissions, firewall drops, route instability, bandwidth spikes, and NAT exhaustion. Anomalies are routed to a four-level severity ladder.

| Level    | Meaning            |
| -------- | ------------------ |
| INFO     | Informational      |
| WARN     | Degraded condition |
| ERROR    | Operational issue  |
| CRITICAL | Severe degradation |

```text
┌ Alerts ─────────────────────────────────────────────┐
│ [WARN] DNS latency exceeded threshold              │
│ [CRIT] Packet loss burst detected                  │
│ [INFO] Route changed on eth0                       │
│ [WARN] Firewall rule dropping excessive traffic    │
└─────────────────────────────────────────────────────┘
```

CRITICAL anomalies trigger the **incident engine**, which snapshots context (top flows, route state, firewall state, recent metrics) into a JSON bundle for forensic replay.

### Replay Engine

Replay mode reconstructs past sessions from persisted metrics, flows, alerts, and route/firewall snapshots.

```bash
testudo replay session-2026-05-23
```

Timeline navigation, flow replay, DNS replay, firewall replay, route replay, NAT replay, topology replay, and full incident reconstruction. Example timeline:

```text
19:42:11  Session started
19:44:02  WARN     DNS latency spike
19:44:15  WARN     Upload saturation
19:44:18  CRITICAL Packet loss burst
19:44:21  ERROR    Firewall drops increasing
```

### Selective PCAP Capture

Raw packets are not persisted by default. Captures are triggered selectively by anomaly events - packet loss bursts, firewall anomalies, DNS failures, retransmission spikes, route instability, NAT exhaustion - and rotated according to retention policy. There is **no always-on full-capture mode** by design.

### TUI Visualizations

- Latency timelines
- Packet-loss heatmaps
- Throughput graphs
- Protocol-distribution graphs
- Alert timelines
- Firewall hit charts
- Flow-activity graphs

```text
Latency Timeline

▁▁▂▂▃▄▅▆▇▆▅▄▃▂▁
```

### Web Interface

The web UI mirrors every TUI view: dashboard, flows, devices, interfaces, routes, firewall, NAT, alerts, settings. Authentication uses bcrypt-hashed credentials stored locally; sessions are cookie-based with an 8-hour TTL. Default user: `testudo` (rotate with `testudo user passwd`).

### Integrations

- **Sentry** - optional, DSN-gated panic and error reporting.
- **Apache Guacamole** - URL deep-link helper for SSH/RDP/VNC handoff from the discovered device inventory.

---

## TUI & Web Interface

The TUI is the canonical interface. The web UI is the same data, the same engine, exposed over HTTP for operators running Testudo on a headless box. Both surface the same tabs - in the same order as the web topbar previewed in the header above:

| Tab        | Purpose                                                                                   |
| ---------- | ----------------------------------------------------------------------------------------- |
| Dashboard  | Network Quality grade, bandwidth per interface, ICMP/DNS sparklines, top flows            |
| Flows      | Live multi-interface flow table with process / DNS / service enrichment; capture controls |
| Devices    | Discovered devices, vendor, open ports; *Scan* + *Connect* (Guacamole / native URI)       |
| Interfaces | Per-interface state, MTU, hardware address, addresses, RX/TX, controls                    |
| Routes     | Routing table, add/remove static routes                                                   |
| Firewall   | `iptables` / `nftables` rule view with hit counters, Testudo-managed rules, add/remove    |
| NAT        | NAT and port-forwarding rules with counters, add/remove                                   |
| TCPDump    | Selective PCAP capture with a BPF filter wizard (proto, host, port, raw filter)           |
| Talkers    | Top hosts, top processes, top services - all ranked by bytes                              |
| Probes     | Interactive runner for ICMP / TCP / UDP / DNS / throughput / traceroute probes            |
| Alerts     | Live alert log with severity filter and free-text search                                  |
| History    | Read-only browse of past sessions persisted to SQLite; anomaly timeline + snapshots       |
| Settings   | Live-tunable thresholds, netops & integrations, **IPFIX flow export** (e.g. to opsanio)   |

Modal configuration is supported in both UIs for firewall rules, NAT rules, port forwarding, interface configuration, route configuration, and alert configuration.

```text
┌ Add Firewall Rule ────────────────────────────────┐
│ Chain:      INPUT                                 │
│ Protocol:   TCP                                   │
│ Port:       443                                   │
│ Action:     ACCEPT                                │
│                                                   │
│ [ Save ]        [ Cancel ]                        │
└───────────────────────────────────────────────────┘
```

---

## Architecture

### Runtime Architecture

```mermaid
flowchart TD
    ICMP[ICMP collector] --> Bus
    DNS[DNS collector] --> Bus
    Cap[AF_PACKET capture<br/>multi-interface] --> Bus
    Disc[Discovery scanner] --> Inventory
    Bus[Event Bus] --> MetricAgg[Metrics aggregator]
    Bus --> FlowAgg[Flow aggregator]
    Bus --> Analyzers[Anomaly analyzers]
    Bus --> Incidents[Incident engine]
    Bus --> Store[(SQLite store)]
    Bus --> TUI
    Bus --> Web[Web UI]
    Settings((Settings store)) -.->|live snapshots| Analyzers
    FlowAgg --> Correlators[Process · DNS · Service]
    Inventory --> Store
    Inventory --> TUI
    Inventory --> Web
    NetOps((netlink ops)) <--> TUI
    NetOps <--> Web
    NetOps --> Kernel[(Linux kernel)]
    Probes((User probes)) --> TUI
    Probes --> CLI
```

### Event-Driven Architecture

```mermaid
flowchart LR
    Collectors --> EventBus
    EventBus --> FlowEngine
    EventBus --> AlertEngine
    EventBus --> FirewallEngine
    EventBus --> RouteEngine
    EventBus --> NATEngine
    EventBus --> ReplayEngine
    EventBus --> StorageEngine
    EventBus --> TUI
    EventBus --> WebUI
```

Every subsystem speaks to one another exclusively through the event bus. There are no direct cross-module calls in the data plane. This isolation is what makes replay possible: a session is reconstructed by feeding persisted events back into the same bus.

### Storage Pipeline

```mermaid
flowchart LR
    Packets[Raw packets] --> Ring[Layer 1<br/>Live ring buffer]
    Ring --> Flows[Layer 2<br/>Flow aggregation]
    Flows --> Metrics[Layer 3<br/>SQLite metrics]
    Anomaly{CRITICAL<br/>anomaly?}
    Ring --> Anomaly
    Anomaly -->|yes| PCAP[Layer 4<br/>Selective PCAP]
    Anomaly -->|no| Drop[Discard]
    Metrics --> Replay[Replay engine]
    PCAP --> Replay
```

### Unified UI Architecture

```mermaid
flowchart TD
    TUI --> CoreEngine
    WebUI --> CoreEngine
    CoreEngine --> FlowEngine
    CoreEngine --> FirewallEngine
    CoreEngine --> RouteEngine
    CoreEngine --> ReplayEngine
    CoreEngine --> AlertEngine
    CoreEngine --> StorageEngine
```

The TUI and the web UI are siblings. They consume snapshots from the same core engine, which means a feature shipped in one is automatically available in the other.

---

## System Design Philosophy

Testudo is built around ten principles that constrain every implementation decision:

1. **Live-first observability.** The default mode is live. Historical analysis is layered on top, not the other way around.
2. **Historical replayability.** Anything you can observe live, you can reconstruct after the fact from a session ID.
3. **Flow aggregation over packet storage.** Raw packets are ephemeral. Flow summaries are what get persisted.
4. **Selective PCAP capture.** Raw packets are kept only when an anomaly justifies it. There is no "always-on full capture" mode by design.
5. **Event-driven processing.** All subsystems talk through one event bus. No direct cross-module data-plane calls.
6. **Low-overhead operation.** Rolling buffers, bounded queues, compressed time-series, no unbounded memory growth.
7. **Linux-first architecture.** Pure-Go netlink, AF_PACKET, `/proc` parsing. No `cgo`, no `libpcap`, no external metrics backend required.
8. **Terminal-first interaction.** The TUI is the canonical interface. The web UI mirrors it; it does not extend it.
9. **Reproducible diagnostics.** Every probe and every operator action is captured as an event for later inspection.
10. **Modular subsystem isolation.** A subsystem can be removed or replaced without touching another subsystem's code.

### Storage Layers

The storage pipeline has four layers, each one less volatile than the last:

| Layer | Medium          | Lifetime              | Purpose                                  |
| ----- | --------------- | --------------------- | ---------------------------------------- |
| 1     | In-memory ring  | Seconds to minutes    | Live rendering, instant anomaly replay   |
| 2     | Flow aggregator | Minutes to hours      | Active flow tracking, enriched summaries |
| 3     | SQLite          | Days to months        | Metrics, alerts, route/firewall history  |
| 4     | Selective PCAP  | Days (incident-bound) | Forensic packet evidence                 |

A typical `FlowSummary` looks like:

```go
type FlowSummary struct {
    Interface   string
    SrcIP       string
    DstIP       string
    Protocol    string
    BytesIn     uint64
    BytesOut    uint64
    AvgLatency  float64
    PacketLoss  float64
    DNSName     string
    ProcessName string
}
```

---

## Prerequisites

Before building or running Testudo, ensure you have:

- **Go**: 1.25 or newer
- **OS**: Linux (Ubuntu / Debian recommended; Fedora, Arch, openSUSE on the roadmap)
- **Kernel privileges**: `CAP_NET_RAW` and `CAP_NET_ADMIN` on the resulting binary (or run as root - not recommended)
- **Disk**: a few hundred MB for SQLite session history and incident-triggered PCAPs
- **Optional**: a Sentry DSN for crash reporting, an Apache Guacamole instance for SSH/RDP/VNC handoff

Testudo is **pure Go**. There is no `cgo` dependency, no `libpcap`, no `libsqlite3`. A clean machine needs only the Go toolchain to build.

---

## Quick Start

1. **Clone**:

   ```bash
   git clone https://github.com/noahzmr/testudo.git
   cd testudo
   ```

2. **Build, mark executable, and install system-wide** - one line that puts `testudo` on your `$PATH`:

   ```bash
   go build -o testudo ./cmd/testudo && chmod +x testudo && sudo mv testudo /usr/local/bin/
   ```

3. **Grant capabilities** (one-time, after install):

   ```bash
   sudo setcap cap_net_raw,cap_net_admin=+ep /usr/local/bin/testudo
   ```

4. **Run from anywhere** in your terminal:

   ```bash
   testudo                              # live TUI, default targets, no capture
   testudo live --capture               # add multi-interface capture
   testudo web                          # start the HTTP UI on 127.0.0.1:8080
   testudo discover --active --lldp     # one-shot layered network scan
   testudo replay session-2026-05-23    # open a past session in replay mode
   ```

5. **Log in to the web UI** (if started). On the first `testudo web` invocation the server provisions a default user `testudo` with a freshly-generated random password printed once to stderr. Rotate it any time with:

   ```bash
   testudo user passwd
   ```

---

## Build Instructions

### Build

```bash
go build -o testudo ./cmd/testudo
```

### Run from source

```bash
go run ./cmd/testudo
```

### Install system-wide

Drop the binary into a directory that's already on your `$PATH` so you can call `testudo` from any shell:

```bash
go build -o testudo ./cmd/testudo \
  && chmod +x testudo \
  && sudo mv testudo /usr/local/bin/
```

Verify:

```bash
which testudo            # /usr/local/bin/testudo
testudo --version
```

### Grant Capabilities (one-time, after install)

```bash
sudo setcap cap_net_raw,cap_net_admin=+ep /usr/local/bin/testudo
```

| Capability      | Used for                                                                          |
| --------------- | --------------------------------------------------------------------------------- |
| `CAP_NET_RAW`   | Raw ICMP, AF_PACKET capture, ARP sweep, LLDP listener, traceroute, ICMP discovery |
| `CAP_NET_ADMIN` | Netlink writes, nftables, promisc-mode interface configuration                    |

Verify:

```bash
getcap /usr/local/bin/testudo
# /usr/local/bin/testudo cap_net_admin,cap_net_raw=ep
```

### Uninstall

```bash
sudo rm /usr/local/bin/testudo
```

### Cross-compile

Testudo is pure Go and cross-compiles cleanly to any `GOOS=linux` target:

```bash
GOOS=linux GOARCH=amd64 go build -o testudo-linux-amd64 ./cmd/testudo
GOOS=linux GOARCH=arm64 go build -o testudo-linux-arm64 ./cmd/testudo
```

### Tests

```bash
go test ./...
```

---

## CLI Reference & Options

```bash
testudo <subcommand> [flags]
```

| Subcommand     | Description                                             |
| -------------- | ------------------------------------------------------- |
| `live`         | Launch the live TUI (default if no subcommand is given) |
| `web`          | Start the HTTP UI                                       |
| `sessions`     | List recorded replay sessions                           |
| `replay <id>`  | Open a replay session                                   |
| `ifaces`       | List interfaces and their state                         |
| `routes`       | Show the routing table                                  |
| `nat list`     | List NAT and port-forwarding rules                      |
| `discover`     | One-shot network scan                                   |
| `probe <host>` | Diagnostic probe against a host                         |
| `user passwd`  | Rotate the local web-UI password                        |

### Common flags

| Flag                      | Default                    | Description                                                                             |
| ------------------------- | -------------------------- | --------------------------------------------------------------------------------------- |
| `--capture`               | off                        | Enable multi-interface AF_PACKET capture                                                |
| `--iface=<csv>`           | auto-discover              | Capture only on the named interfaces (e.g. `wlp1s0,wg0`)                                |
| `--exclude-iface=<csv>`   | none                       | Skip the named interfaces during auto-discovery                                         |
| `--allow-netops-write`    | off                        | Permit route/interface/NAT writes from the TUI                                          |
| `--listen=<addr>`         | `127.0.0.1:8080`           | Web UI listen address (`web` subcommand)                                                |
| `--active`                | off                        | Active discovery - ARP broadcast sweep + ICMP sweep + mDNS query + SNMPv2c (`discover`) |
| `--lldp`                  | on                         | Passive LLDP listener for directly-connected neighbours (`discover`)                    |
| `--snmp-community=<str>`  | `public`                   | SNMPv2c read community; empty string disables SNMP (`discover`)                         |
| `--snmp-timeout=<dur>`    | `1s`                       | Per-host SNMP UDP/161 deadline (`discover`)                                             |
| `--max-subnet-bits=<int>` | `10`                       | Cap subnet expansion for active sweeps; 10 = /22 = 1024 hosts (`discover`)              |
| `--wait=<dur>`            | `6s`                       | Discovery dwell time / LLDP listen window (`discover`)                                  |
| `--config=<path>`         | `~/.testudo/settings.json` | Override the persistent settings path                                                   |
| `--log-level=<level>`     | `info`                     | `debug` / `info` / `warn` / `error`                                                     |
| `--no-color`              | off                        | Disable ANSI color in the TUI                                                           |
| `--version`               | -                          | Print version and exit                                                                  |
| `--help`                  | -                          | Print help and exit                                                                     |

### Examples

```bash
testudo                                       # live TUI, default targets, no capture
testudo live --capture                        # add multi-interface capture (auto-discover)
testudo live --iface=wlp1s0,wg0               # capture on specific interfaces
testudo live --allow-netops-write             # permit route/interface/NAT writes from TUI
testudo web --listen=0.0.0.0:8443             # bind the web UI to all interfaces
testudo discover --active --lldp --wait 8s    # full layered scan: ARP sweep + ICMP + mDNS + SNMP + LLDP
testudo discover --snmp-community=monitoring  # SNMPv2c probe with a non-default community
testudo discover --max-subnet-bits=8          # restrict active sweeps to /24
testudo replay session-2026-05-23             # open a past session in replay mode
```

---

## Configuration System

Testudo ships with intelligent defaults. Every threshold is live-tunable from the Settings tab in the TUI, from the Settings panel in the web UI, and from the persisted config file at `~/.testudo/settings.json`.

### Anomaly Thresholds

| Setting           | Default | Description                                      |
| ----------------- | ------- | ------------------------------------------------ |
| Packet loss       | 2 %     | Rolling 20-sample loss percentage                |
| DNS latency       | 120 ms  | Per-query DNS warning threshold                  |
| Jitter            | 20 ms   | Mean RTT delta over the last 20 samples          |
| RTT               | 150 ms  | Single-sample ICMP round-trip warning            |
| Retransmissions   | 5 %     | TCP retransmission warning threshold             |
| Incident cooldown | 60 s    | Minimum seconds between incident bundle triggers |

### Retention & Capture

| Setting              | Default       | Description                              |
| -------------------- | ------------- | ---------------------------------------- |
| Replay retention     | 30 days       | Session metrics kept in SQLite           |
| PCAP retention       | 7 days        | Incident-triggered PCAP rotation horizon |
| Smart PCAP capture   | enabled       | Trigger captures from CRITICAL anomalies |
| Capture interfaces   | auto-discover | Comma-separated interface override       |
| Interface exclusions | none          | Interfaces to skip during auto-discovery |

### Discovery

| Setting                  | Default  | Description                                                                               |
| ------------------------ | -------- | ----------------------------------------------------------------------------------------- |
| `DiscoveryEnabled`       | true     | Master toggle for the discovery scanner (passive listeners + scheduler)                   |
| `DiscoveryActive`        | false    | Enable active probes: ARP broadcast sweep, ICMP sweep, mDNS query, SNMPv2c GET            |
| `DiscoveryInterval`      | 60 s     | Cadence of one discovery round                                                            |
| `DiscoveryMaxSubnetBits` | 10       | Prefix-expansion cap; 10 = /22 (1024 hosts), 8 = /24, 12 = /20, wider is silently skipped |
| `LLDPEnabled`            | true     | Passive LLDP listener (needs `CAP_NET_RAW`; soft-fails per interface when missing)        |
| `SNMPCommunity`          | `public` | SNMPv2c read community; empty string disables SNMP probing entirely                       |
| `SNMPTimeout`            | 1 s      | Per-host SNMP UDP/161 deadline                                                            |

### Integrations

| Setting        | Default | Description                         |
| -------------- | ------- | ----------------------------------- |
| Sentry DSN     | unset   | Enable Sentry panic/error reporting |
| Guacamole base | unset   | Base URL for the Guacamole instance |

### Settings View

```text
┌ Settings ───────────────────────────────────────────┐
│ Packet Loss Threshold:     2 %                     │
│ DNS Warning Threshold:     120 ms                  │
│ Replay Retention:          30 days                 │
│ Smart PCAP Capture:        Enabled                 │
└─────────────────────────────────────────────────────┘
```

---

## Network Quality Grade

The dashboard's most prominent element is a single **letter grade** (A+ through F) with a 0-100 score next to it. It's meant to be the one thing you glance at to answer *"is the network OK right now?"* before you dive into any specific tab.

```text
┌ Network Quality ──────────────────────────────────────┐
│                                                       │
│   ┌─────┐    92 / 100                                 │
│   │  A  │    Very good                                │
│   └─────┘                                             │
│                                                       │
│   Loss   0.1 %   ok   ▏  RTT     18 ms    ok          │
│   Jitter 4 ms    ok   ▏  DNS     22 ms    ok          │
│                                                       │
└───────────────────────────────────────────────────────┘
```

### What goes into the grade

Four live measurements, each pulled from the metrics aggregator. Every measurement is scaled into its own **0-100 sub-score** and the four sub-scores are combined with weights:

| Sub-score       | Weight | What it measures                                          |
| --------------- | ------ | --------------------------------------------------------- |
| **Packet loss** | 40 %   | Average loss percentage across configured ICMP targets    |
| **RTT**         | 30 %   | Average round-trip latency across configured ICMP targets |
| **Jitter**      | 15 %   | Rolling RTT variation across configured ICMP targets      |
| **DNS latency** | 15 %   | Average resolution time across configured DNS resolvers   |

Loss carries the biggest weight because it's the most visceral kind of degradation - a video call that pixelates or a download that stalls almost always starts with loss. Jitter weighs least because real-world links jitter a little even when nothing is wrong.

### How a measurement becomes a sub-score

Each sub-score is anchored to the matching **threshold** from the Settings tab (see [Anomaly Thresholds](#anomaly-thresholds)). The mapping is linear in two segments:

| Measured value           | Sub-score |
| ------------------------ | --------- |
| `0` (perfect)            | **100**   |
| `threshold` (comfort)    | **50**    |
| `2 × threshold` or worse | **0**     |

So with the default threshold for packet loss of **2 %**:

| Real-world loss | Loss sub-score  |
| --------------- | --------------- |
| 0 %             | 100             |
| 0.5 %           | ~87             |
| 1.0 %           | 75              |
| 2.0 %           | 50  *(comfort)* |
| 3.0 %           | 25  *(painful)* |
| 4.0 % or more   | 0               |

The same shape applies to RTT (threshold 150 ms), Jitter (20 ms) and DNS (120 ms). Tune the thresholds in Settings if your environment is faster or slower than the defaults - the grade re-scales automatically.

**Empty inputs map to a neutral 100.** "Nothing measured yet" should not paint the dashboard red on first start.

### From total score to letter

The four sub-scores are weighted, summed, rounded, and run through this ladder:

| Score range | Letter | Verdict    | Colour | Roughly means…                                                            |
| ----------- | ------ | ---------- | ------ | ------------------------------------------------------------------------- |
| 95 - 100    | **A+** | Excellent  | green  | Effectively at the noise floor. Nothing to investigate.                   |
| 90 - 94     | **A**  | Very good  | green  | Healthy. Small natural jitter, no loss.                                   |
| 85 - 89     | **A-** | Good       | green  | Normal day-to-day - typical wired LAN or solid Wi-Fi.                     |
| 80 - 84     | **B+** | OK         | yellow | One sub-score brushing its comfort line; everything still usable.         |
| 70 - 79     | **B**  | Acceptable | yellow | Background noise that humans notice (slight lag, occasional stutter).     |
| 60 - 69     | **C**  | Degraded   | orange | One or more sub-scores past the threshold; calls and streams will hiccup. |
| 50 - 59     | **D**  | Poor       | red    | Multiple sub-scores in the painful zone; expect complaints.               |
| 0 - 49      | **F**  | Failing    | red    | Network is meaningfully broken; open the Alerts tab and start digging.    |

### When to expect each grade

Some realistic ballparks - useful for calibrating your own expectations:

| Environment                            | Typical grade | Why                                                                  |
| -------------------------------------- | ------------- | -------------------------------------------------------------------- |
| Wired LAN to a local gateway           | **A+ / A**    | Sub-millisecond RTT, no loss, DNS resolved by the local resolver.    |
| Good home Wi-Fi to the internet        | **A / A-**    | 10-30 ms RTT, sub-percent loss, DNS in the 20-50 ms range.           |
| Office VPN over a healthy ISP          | **A- / B+**   | 30-80 ms RTT, occasional micro-jitter, DNS sometimes >80 ms.         |
| Saturated uplink (someone's uploading) | **B / C**     | RTT and jitter both climb; loss stays low until the queue overflows. |
| Wi-Fi at the edge of coverage          | **C / D**     | Retransmissions push effective loss up; jitter doubles or triples.   |
| Misconfigured DNS, healthy link        | **B+ / B**    | Loss/RTT/jitter look great but DNS latency drags the total down.     |
| Real outage in progress                | **F**         | Loss spikes, RTT explodes or times out, DNS fails to resolve.        |

A persistent grade below **B** usually means something deserves an open ticket - either reality has changed (new neighbour on the spectrum, ISP route flap, NIC negotiating down) or the thresholds are set for a quieter network than the one you actually have.

### Practical reading tips

- **Watch the trend, not the single number.** A dashboard sitting at A- all day is healthier than one bouncing between A+ and C.
- **Look at the sub-scores when the letter drops.** Each sub-score line shows the raw value and an `ok` / `over` flag - the one tagged `over` is the metric to investigate first.
- **The grade is per-host.** It reflects how *this* Linux box is experiencing the network. Two Testudo instances on the same LAN can legitimately show different grades.
- **Replay sessions show the grade for that moment in time.** Scrolling back through a session is the cleanest way to find *when* the grade first dropped.

---

## Directory Structure

```text
testudo/
├── cmd/
│   └── testudo/                ← CLI entry point + subcommand registry
├── internal/
│   ├── tui/                    ← Bubble Tea TUI
│   ├── web/                    ← HTTP UI + embedded assets
│   ├── engine/                 ← lifecycle orchestrator
│   ├── events/                 ← event bus + severity ladder
│   ├── collectors/             ← ICMP, DNS probes
│   ├── capture/                ← multi-interface AF_PACKET
│   ├── flows/                  ← flow aggregator + correlators
│   ├── analyzers/              ← anomaly detectors
│   ├── alerts/                 ← alert log + severity escalation
│   ├── firewall/               ← iptables / nftables
│   ├── routes/                 ← routing table ops
│   ├── nat/                    ← NAT + port forwarding
│   ├── discovery/              ← ARP / ICMP / mDNS scanner
│   ├── interfaces/             ← interface enumeration & control
│   ├── metrics/                ← rolling per-target stats
│   ├── replay/                 ← session reconstruction
│   ├── storage/                ← SQLite persistence
│   ├── integrations/
│   │   ├── sentry/             ← optional panic reporting
│   │   └── guacamole/          ← SSH/RDP/VNC deep-link helper
│   └── config/                 ← defaults + persistent settings
├── storage/
│   ├── captures/               ← incident-triggered PCAP (gitignored)
│   ├── metrics/                ← downsampled metrics export
│   └── sessions/               ← per-session artifacts
├── docs/
│   └── images/                 ← screenshots referenced in README
├── README.md
├── DEVELOPER.md
├── LICENSE
├── NOTICE
├── COPYRIGHT_HEADER.txt
├── go.mod
└── go.sum
```

---

## Development Guide

### Module Overview

| Package                           | Responsibility                                                      |
| --------------------------------- | ------------------------------------------------------------------- |
| `internal/tui`                    | Bubble Tea application - tabs, modals, browser, replay UI           |
| `internal/web`                    | HTTP UI, embedded assets, sessions, snapshot endpoint               |
| `internal/engine`                 | Lifecycle orchestrator - wires all subsystems together              |
| `internal/events`                 | Non-blocking fan-out event bus, four-level severity                 |
| `internal/collectors`             | ICMP and DNS probes                                                 |
| `internal/capture`                | Multi-interface AF_PACKET capture                                   |
| `internal/flows`                  | Interface-tagged five-tuple aggregator, correlators                 |
| `internal/firewall`               | iptables / nftables observation and management                      |
| `internal/nat`                    | NAT rule management and port-forward bookkeeping                    |
| `internal/routes`                 | Routing table observation and management                            |
| `internal/discovery`              | ARP, ICMP, mDNS scanner with device inventory                       |
| `internal/alerts`                 | Anomaly detector pipeline, severity escalation, alert log           |
| `internal/replay`                 | Session reconstruction from persisted events                        |
| `internal/storage`                | SQLite persistence (sessions, samples, flows, anomalies, incidents) |
| `internal/integrations/sentry`    | Optional panic/error reporting                                      |
| `internal/integrations/guacamole` | URL deep-link helper for SSH/RDP/VNC handoff                        |
| `internal/config`                 | Defaults, thresholds, persistent settings store                     |
| `cmd/testudo`                     | Command-line entry point and subcommand registry                    |

### Coding Standards

- **Avoid global state.** All subsystem state is owned by a struct and passed explicitly.
- **`context.Context` everywhere.** Every cancellable operation accepts a context as its first argument.
- **Channels over locks.** Coordination uses channels; locks are reserved for short, contended critical sections.
- **Never block the render loop.** The TUI render goroutine must remain responsive; analysis runs on workers.
- **Isolated analyzers.** Each anomaly detector is a self-contained unit that consumes events and emits anomalies.
- **Modular subsystems.** A subsystem should be removable without touching another subsystem's code.
- **Structured logging.** Every log line is structured key/value, never freeform text.

### Performance Rules

- Never render raw packets directly to the UI.
- Minimize allocations on hot paths (capture, aggregation, event dispatch).
- Use rolling buffers with fixed capacity for live data.
- Compress historical metrics before persisting.
- Avoid unbounded memory growth - every buffer has a documented ceiling.
- Process asynchronously where possible; the event bus is the synchronization point.

### Event-Driven Flow

Every observable signal in Testudo travels the same path:

```text
Collector ──► EventBus ──► Subscribers ──► (UI, Storage, Analyzers, Replay)
```

A subscriber never calls back into a collector. If a subscriber needs to act on the network, it emits an `OpsRequest` event and a netops subsystem handles it. This keeps the data plane and the control plane cleanly separated.

For the full developer walkthrough - adding subsystems, release process, test conventions - see [DEVELOPER.md](./DEVELOPER.md).

---

## Further Documentation

This README is the top-level tour. The rest of the project is documented in a small set of focused Markdown files - each one is meant to be read on its own, no chasing forward-references required.

### Top-level

| Document                                       | Audience     | What's inside                                                                                       |
| ---------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------- |
| [README.md](./README.md)                       | everyone     | This file - overview, install, features, configuration, glossary, roadmap.                          |
| [DEVELOPER.md](./DEVELOPER.md)                 | contributors | Build & run, repository layout, architecture in 60 seconds, adding a subsystem, testing, releasing. |
| [LICENSE](./LICENSE)                           | everyone     | MPL-2.0 license text in full.                                                                       |
| [NOTICE](./NOTICE)                             | everyone     | Branding restrictions, required attribution when redistributing.                                    |
| [COPYRIGHT_HEADER.txt](./COPYRIGHT_HEADER.txt) | contributors | The standard copyright header that every new source file must carry.                                |

### `docs/` - deep-dives

The [docs/](./docs/) directory hosts the longer technical writeups. Start at [docs/README.md](./docs/README.md) for the index, or jump straight to a topic:

| Document                                       | Audience             | Summary                                                                                                 |
| ---------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------- |
| [docs/README.md](./docs/README.md)             | everyone             | Index of the docs folder with one-line summaries.                                                       |
| [docs/architecture.md](./docs/architecture.md) | engineers            | Subsystem map (Mermaid), data flow, module boundaries, lifecycle.                                       |
| [docs/storage.md](./docs/storage.md)           | engineers, operators | The four storage layers (live ring => flow aggregator => SQLite => selective PCAP) and their lifetimes. |
| [docs/replay.md](./docs/replay.md)             | operators            | Session capture, the replay engine, timeline navigation, what's persisted and what isn't.               |
| [docs/firewall.md](./docs/firewall.md)         | operators            | `nftables` (default) and `iptables` (fallback) backends; chain semantics; common rule recipes.          |
| [docs/topology.md](./docs/topology.md)         | operators            | Passive topology graph - nodes, edges, sources (ARP / LLDP / SNMP / flow observation).                  |
| [docs/alerts.md](./docs/alerts.md)             | operators            | Severity levels, default thresholds, the anomaly engine, incident bundles.                              |

### Pointing readers to the right place

| If you want to…                         | Read…                                                                         |
| --------------------------------------- | ----------------------------------------------------------------------------- |
| Get up and running fast                 | [Quick Start](#quick-start) in this README                                    |
| Understand what each tab does           | [TUI & Web Interface](#tui--web-interface) in this README                     |
| Read the grade on the dashboard         | [Network Quality Grade](#network-quality-grade) in this README                |
| Learn networking vocabulary             | [Glossary](#glossary---networking-terms-for-beginners) in this README         |
| Understand how subsystems wire together | [docs/architecture.md](./docs/architecture.md)                                |
| Know what Testudo keeps on disk         | [docs/storage.md](./docs/storage.md)                                          |
| Write a firewall rule from the TUI      | [docs/firewall.md](./docs/firewall.md)                                        |
| Investigate an incident after the fact  | [docs/replay.md](./docs/replay.md) + [docs/alerts.md](./docs/alerts.md)       |
| Contribute code                         | [DEVELOPER.md](./DEVELOPER.md) + [CONTRIBUTING section](#contributing)        |
| Fork or rebrand                         | [LICENSE](./LICENSE) + [NOTICE](./NOTICE) + the [Branding section](#branding) |

If a topic isn't covered yet, check `.claude/CLAUDE.md` (the canonical project spec) or open an issue.

---

## Screens

![Dashboard](docs/images/dashboard.png)

![Flows](docs/images/flows.png)

![Devices](docs/images/devices.png)

![Firewall](docs/images/firewall.png)

![Alerts](docs/images/alerts.png)

![Web UI](docs/images/web-ui.png)

---

## Glossary - Networking Terms for Beginners

New to networking? No worries - this section is a quick, plain-language cheat sheet for the terms that show up around Testudo and in network troubleshooting generally. You can read it top-to-bottom or just grep it when something looks unfamiliar.

> *Tip: if you only learn three things from this glossary, make them **IP address**, **port**, and **packet**. Almost everything else is built on those.*

### The absolute basics

| Term            | What it actually means                                                                                                                  |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Packet**      | A small chunk of data sent across the network. Networks don't send files - they send thousands of packets that get reassembled.         |
| **IP address**  | The "street address" of a device on a network. IPv4 looks like `192.168.1.10`; IPv6 looks like `2a01:abcd::1`.                          |
| **MAC address** | The hardware address baked into a network card. Looks like `aa:bb:cc:dd:ee:ff`. Used on the local cable/Wi-Fi, not across the internet. |
| **Port**        | A number from 0-65535 that says *which app* on a device should receive a packet. Web is 80/443, SSH is 22, DNS is 53.                   |
| **Protocol**    | The "language" two devices agree to speak. Common ones: TCP, UDP, ICMP.                                                                 |
| **Interface**   | A network port on your device. `eth0` is wired, `wlan0` is Wi-Fi, `wg0` is a WireGuard VPN, `docker0` is a container bridge, etc.       |
| **Host**        | Any device on the network - a server, laptop, phone, printer, fridge, whatever.                                                         |

### Common protocols you'll see in Testudo

| Term     | Plain-language version                                                                                                                                                                 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **TCP**  | Reliable conversation. Both sides confirm what was received. Used for the web, SSH, file transfer.                                                                                     |
| **UDP**  | Fire-and-forget messages. No confirmation. Used for DNS lookups, voice, video, games.                                                                                                  |
| **ICMP** | The "are you alive?" protocol. `ping` and `traceroute` both use it.                                                                                                                    |
| **DNS**  | The phone book. Turns `youtube.com` into an IP address your machine can actually reach.                                                                                                |
| **ARP**  | "Who has IP `192.168.1.5`? Tell me your MAC." Used so devices on the same LAN can find each other.                                                                                     |
| **mDNS** | Multicast DNS - DNS but for the local network. How printers, Chromecasts and your laptop announce themselves to your home Wi-Fi.                                                       |
| **LLDP** | Link Layer Discovery Protocol. Switches and APs broadcast "hi, I'm switch SW-CORE-01, port 12, I'm a switch with bridge capability." Testudo listens for this for free identification. |
| **SNMP** | Simple Network Management Protocol. The classic way to ask routers and switches "what's your name? how long have you been up? how many interfaces do you have?"                        |

### How traffic is named and counted

| Term               | What it means                                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Flow / 5-tuple** | A single conversation between two endpoints, identified by (source IP, source port, dest IP, dest port, protocol). One TCP connection = one flow. |
| **Throughput**     | How many bytes per second are moving. Usually quoted in Mb/s or MB/s.                                                                             |
| **RTT**            | Round-Trip Time. How long a packet takes to go to the other side and come back. The fundamental "is it slow?" number.                             |
| **Jitter**         | How *steady* RTT is. Low RTT but jittery = unstable. Bad for voice and video.                                                                     |
| **Packet loss**    | What fraction of packets never made it. Anything above ~2 % is noticeable; above ~5 % is painful.                                                 |
| **Retransmission** | TCP noticed a packet got lost and sent it again. High retransmissions = something on the path is dropping traffic.                                |
| **Saturation**     | The link is at its bandwidth limit. Symptoms: latency spikes, packet loss, queue buildup.                                                         |

### Capturing and looking at packets

| Term                 | What it means                                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **PCAP**             | A file format for saved raw packets. The thing `tcpdump` and Wireshark write. Testudo only saves PCAPs when something interesting happens.                         |
| **tcpdump**          | The classic command-line packet sniffer. Testudo replaces "always-on tcpdump" with selective capture.                                                              |
| **Wireshark**        | The classic GUI packet sniffer.                                                                                                                                    |
| **AF_PACKET**        | The Linux kernel API that lets a program read every packet that crosses an interface. Testudo uses it directly - no `libpcap` needed.                              |
| **libpcap**          | The C library most packet tools use to capture packets. Testudo deliberately avoids it (pure Go).                                                                  |
| **Promiscuous mode** | An interface setting that says "give me *every* packet you see, not just ones addressed to me." Needed for full capture on a switch port that's mirroring traffic. |

### Routing, NAT, and firewalls

| Term                       | What it means                                                                                                                                                           |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Routing table**          | The list of rules that tells your machine "to reach network X, send the packet to gateway Y on interface Z."                                                            |
| **Gateway**                | The next-hop router your machine sends traffic to when the destination isn't on the same subnet. Usually `192.168.1.1` at home.                                         |
| **NAT**                    | Network Address Translation. The trick that lets dozens of devices behind one home router share a single public IP.                                                     |
| **Port forwarding (DNAT)** | "Anything that arrives at my public IP on port 443, send it to the web server at `192.168.1.10:443`." A specific kind of NAT.                                           |
| **Masquerading**           | Source NAT, the variant home routers use to rewrite outbound traffic so it looks like it came from the router.                                                          |
| **Firewall**               | The kernel's "rules about which packets are allowed in/out." On Linux today that's `iptables` (older) or `nftables` (newer). `firewalld` is a friendly wrapper.         |
| **Chain**                  | A list of firewall rules evaluated in order. `INPUT` is for traffic destined to your box, `OUTPUT` is for traffic leaving it, `FORWARD` is for traffic passing through. |
| **ACCEPT / DROP**          | The two main verdicts a firewall rule can deliver. `ACCEPT` lets it through, `DROP` silently throws it away.                                                            |
| **Conntrack**              | The kernel's connection-tracking table. Remembers "I've seen this TCP flow before" so reply packets get matched to the right NAT/firewall state.                        |

### Networks and subnets (the slash numbers)

| Term             | What it means                                                                                                                                                         |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Subnet**       | A range of IP addresses that share the same local network. `192.168.1.0/24` means "all addresses from `192.168.1.0` to `192.168.1.255`."                              |
| **CIDR / `/24`** | The slash number says *how many bits are fixed* in the network address. `/24` = 256 hosts, `/22` = 1024 hosts, `/16` = 65 536 hosts. Smaller number = bigger network. |
| **Broadcast**    | A special address that means "everyone on this subnet." ARP requests are broadcast.                                                                                   |
| **Loopback**     | The `127.0.0.1` interface - your machine talking to itself. Always there, never on the wire.                                                                          |

### Linux-specific bits you'll see in this README

| Term                       | What it means                                                                                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`/proc`**                | The Linux "virtual filesystem" that exposes kernel state as files. `/proc/net/arp`, `/proc/net/tcp`, `/proc/<pid>/fd` etc. Testudo reads these directly. |
| **Netlink**                | The kernel API for talking to networking subsystems (routes, interfaces, firewall). Used instead of running `ip` or `iptables` in a subshell.            |
| **Capabilities (`CAP_*`)** | Fine-grained permissions that replace "needs root." `CAP_NET_RAW` lets a program open raw sockets without being root.                                    |
| **`setcap`**               | The command that grants a binary a capability. Testudo uses it so you don't have to run the tool as root.                                                |
| **VLAN**                   | Virtual LAN. A way to run several logical networks over one physical cable. Identified by a tag number (e.g. VLAN 100).                                  |
| **Bridge**                 | A virtual switch inside Linux. Containers and VMs usually plug into one (`docker0`, `br0`).                                                              |
| **Tunnel / VPN**           | An encrypted "fake cable" between two machines over the public internet. WireGuard, OpenVPN, IPsec are common implementations.                           |

### Putting it all together - a worked example

When you open a web page, here is what just happened in glossary terms:

1. Your browser asks **DNS** to turn `example.com` into an **IP address**.
2. The kernel checks its **routing table** to decide which **interface** and **gateway** to send the packet through.
3. On the local network, it uses **ARP** to find the **MAC address** of that gateway.
4. The packet (one of many) is **NAT**-ed by the home router so the reply can find its way back.
5. The remote server replies with **TCP** packets carrying the HTML, which the kernel reassembles.
6. **Conntrack** remembers the flow so subsequent reply packets are matched to the same conversation.
7. Testudo (if running) sees the whole thing as a single **flow** with an **RTT**, **throughput**, **jitter** and **packet-loss** number attached.

That's the entire short version of "how the internet works" - and Testudo's job is to let you watch each of those steps as they happen, or after they've already happened.

---

## Roadmap

Roughly ordered by what's next. Each milestone is shaped around one theme so users and contributors can tell at a glance whether a release affects them.

**Legend**

| Symbol | Meaning                       |
| ------ | ----------------------------- |
| `+`    | New feature                   |
| `!`    | Infrastructure change         |
| `#`    | UI / Visualization            |
| `★`    | Headline goal for the release |

### v0.2 - Cross-Platform Compatibility *(next up)*

The single biggest thing holding Testudo back today is being pinned to Ubuntu/Debian. v0.2 is about getting it to *just work* on the rest of the Linux ecosystem and on macOS.

- `★` Verified install, build, and live capture on **Fedora**, **openSUSE**, **Arch Linux**, **RHEL / Rocky / Alma**, **Alpine**, and **NixOS**.
- `+` **macOS port** - BPF/`PF_ROUTE` capture path replacing the Linux AF_PACKET socket; route, interface and firewall (pf) read-only views on the same TUI/Web UI.
- `+` `firewalld` backend alongside `iptables` / `nftables` for RHEL-family installs.
- `!` Per-distro packaging: `.deb`, `.rpm`, AUR `PKGBUILD`, Alpine `apk`, Homebrew tap.
- `!` CI matrix that builds and smoke-tests on every supported distro per PR.
- `#` Per-platform capability hints in the welcome banner ("on macOS use `sudo ./testudo` or grant the `com.apple.security.network.client` entitlement").

### v0.3 - IPFIX Export & opsanio Integration

Testudo already speaks **IETF IPFIX** (RFC 7011) for flow export. v0.3 hardens that exporter for production collectors and ships first-class integration with **[opsanio](https://autonubil.de/home#appliances)** - the autonubil GmbH monitoring appliance line that Testudo is designed to feed.

- `★` **First-class opsanio integration.** opsanio is autonubil's turnkey on-prem monitoring appliance. Testudo can already export flow records to it over IPFIX; v0.3 makes it a single Settings toggle, with auto-discovery of an opsanio collector on the local subnet and a pre-built information element template matched to opsanio's dashboards. See <https://autonubil.de/home#appliances> for the appliance line-up.
- `+` IPFIX exporter parity with other common collectors (ipfixcol2, nProbe, Elastic ingest, ntopng) - same template, same field set.
- `+` Configurable IPFIX template profiles: minimal (5-tuple + bytes/packets), standard (+ ifindex, ToS, TCP flags), forensic (+ DNS name, process name, NAT state).
- `+` IPFIX flow sampling and rate-limiting for high-throughput links.
- `#` Live "IPFIX export" panel in the dashboard: target collector, records/sec, last error.

### v0.4 - Forensic Depth

- `+` Per-flow PCAP slicing during incident bundles.
- `+` Topology diff between replay sessions.
- `#` Incident overlay on the dashboard sparkline and the quality grade.
- `!` Compressed metrics export format (zstd).

### v0.5 - Distributed Operation

- `+` Multi-host session aggregation.
- `+` Read-only federation for the web UI.
- `!` Optional remote PostgreSQL backend for long-horizon retention.
- `#` Cross-host topology view.

### v1.0 - Production Hardening

- `+` IPv6 parity across discovery and firewall modules.
- `!` Long-running stability soak harness.
- `#` Operator-mode keybinding overlay in the TUI.
- `+` Stable plugin API for third-party collectors.
- `+` Stable plugin API for third-party collectors

---

## Contributing

Contributions are welcome. The [Development Guide](#development-guide) above and the philosophy in [.claude/CLAUDE.md](./.claude/CLAUDE.md) describe how the project is organized and what kinds of changes fit its design.

The short version:

1. Fork the repository and create a feature branch.
2. Add or extend a subsystem under `internal/` - keep it removable.
3. Wire it into the event bus, not into another subsystem.
4. Include tests under the same package (`*_test.go`).
5. Run `go test ./...` and `go vet ./...` before opening a PR.
6. Stamp every new source file with the standard header from [COPYRIGHT_HEADER.txt](./COPYRIGHT_HEADER.txt).
7. Open a PR with a focused description; small PRs land faster than sweeping ones.

Contributions are accepted under the same MPL-2.0 license as the rest of the project.

---

## License

Testudo is distributed under the **Mozilla Public License Version 2.0** ([LICENSE](./LICENSE)), with additional branding restrictions documented in [NOTICE](./NOTICE).

Copyright (c) 2026 Noah Zeumer.

### Why MPL-2.0

MPL-2.0 was chosen deliberately. It strikes the balance Testudo needs:

- **File-level copyleft.** Modifications to MPL-licensed files must remain open under the same license, but linking Testudo against proprietary code is permitted. This keeps the core honest without making the project hostile to commercial adopters.
- **Commercial use is welcome.** Companies can deploy, modify, and ship Testudo internally or as part of larger commercial offerings.
- **Modifications stay visible.** Anyone who improves an MPL-licensed file must publish the modified source - bug fixes and improvements flow back to the community.
- **Compatible with permissive ecosystems.** MPL-2.0 plays well with Apache-2.0 and BSD-licensed dependencies, which makes up most of the Go ecosystem.

### What You Can Do

- Use Testudo in production, including commercial deployments.
- Modify the source code for your own needs.
- Fork the repository.
- Redistribute the source or compiled binaries.
- Build derivative works.
- Contribute changes back upstream.

### What You Cannot Do

- Remove the Testudo branding, ASCII banner, or attribution from forks or redistributions.
- Re-release Testudo under a different product name as if it were a new project.
- Strip the `NOTICE` file or its branding clauses.
- Misrepresent authorship of the original work.
- Remove copyright headers from individual source files.

The code license and the branding restrictions are deliberately separated: MPL-2.0 governs the code, the `NOTICE` file governs the brand. Read both before forking.

---

## Branding

The name **Testudo**, the ASCII logo, and the project identity are property of Noah Zeumer and are not granted under the MPL-2.0 source-code license. The full branding terms - including what attribution is required when redistributing, when a derivative work must be renamed, and how the ASCII banner may and may not be reused - are documented in [NOTICE](./NOTICE).

In short: **fork freely, modify freely, redistribute freely. If you ship a substantively different product, give it a different name.**

---

## Acknowledgments

Testudo stands on the shoulders of giants in the Go and Linux ecosystems:

- **[Bubble Tea](https://github.com/charmbracelet/bubbletea)** - the Elm-inspired TUI runtime that drives the terminal interface.
- **[Lip Gloss](https://github.com/charmbracelet/lipgloss)** - styling and layout for the TUI.
- **[gopacket](https://github.com/google/gopacket)** - packet decoding for the AF_PACKET capture pipeline.
- **[mdlayher/netlink](https://github.com/mdlayher/netlink)** and **[vishvananda/netlink](https://github.com/vishvananda/netlink)** - pure-Go netlink for `cgo`-free kernel interaction.
- **[google/nftables](https://github.com/google/nftables)** - the nftables backend for the firewall subsystem.
- **AF_PACKET, netfilter, conntrack, and `/proc`** - the Linux primitives that make any of this possible.
- **IEEE 802.1AB (LLDP)** and **SNMPv2c** - the open standards that let Testudo identify managed devices without sending a probe.
- **[modernc.org/sqlite](https://gitlab.com/cznic/sqlite)** - pure-Go SQLite, the embedded persistence backend.
- **Sentry** and **Apache Guacamole** - optional integrations for crash reporting and console handoff.

And to every operator who has stared at six terminals during an incident and thought *"there has to be a better way"* - this is for you.
