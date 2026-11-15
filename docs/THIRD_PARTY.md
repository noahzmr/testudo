# Third-party software

Testudo itself is licensed under MPL-2.0 (see `LICENSE` and `NOTICE`).

Licenses below were checked against each project's repository on 2026-11-14.
Re-check before adding a dependency or reusing anything.

## Reference projects

Studied for architecture, feature scope and user experience. **No code has
been copied from any of them.**

| Project | License | Use | May code be reused in Testudo? |
| --- | --- | --- | --- |
| OPNsense (`opnsense/core`) | BSD-2-Clause | reference: rule model, aliases, apply and rollback | compatible with attribution; nothing reused |
| FRRouting | GPL-2.0-or-later for most files (per-file SPDX headers) | runtime dependency: separate daemon, driven through `vtysh` and `frr-reload.py` by the runner | no. Run as a separate program only; do not copy or link |
| Pangolin (`fosrl/pangolin`) | AGPL-3.0 for most files, a commercial license for marked files | reference: identity-aware access over WireGuard | no. Ideas only |
| WireGuard kernel module | GPL-2.0 | runtime: kernel data plane | not applicable (kernel) |
| wireguard-tools | GPL-2.0 | reference only; Testudo does not call `wg` or `wg-quick` | no |
| wireguard-go, wgctrl-go | MIT | `wgctrl` is an existing dependency | yes, with attribution |
| Traefik | MIT | runtime dependency: separate daemon, started by the runner and configured through files ([ADR 0001](adr/0001-managed-traefik-vs-native-proxy.md)); tested with v3.3.4 | yes, with attribution; nothing reused |
| hashicorp/raft, raft-boltdb | MPL-2.0 | planned Go dependency ([ADR 0002](adr/0002-raft-library.md)) | as a module |
| etcd-io/raft | Apache-2.0 | evaluated alternative | as a module |
| etcd-io/bbolt | MIT | planned, through the Raft log store | as a module |
| nftables (`nft`) | GPL-2.0 | runtime dependency: executed by the nft runner to check and load rulesets | no. Run as a separate program only |
| keepalived | GPL-2.0 | planned runtime dependency: separate daemon | no |
| conntrack-tools (conntrackd) | GPL-2.0 | planned runtime dependency: separate daemon | no |
| Siemens Software-Defined Systems | not software; published material | principle only | not applicable |

Separate daemons under GPL or AGPL are executed and configured, never linked
or copied, so their terms do not extend to Testudo's source.

## Planned Go dependencies (not yet added)

| Module | License | For |
| --- | --- | --- |
| `github.com/coreos/go-oidc` | Apache-2.0 | OIDC discovery and token verification |
| `github.com/msteinert/pam` | BSD-2-Clause | Linux-PAM binding (needs cgo, which is accepted) |

## Direct Go dependencies today

| Module | Version | License |
| --- | --- | --- |
| `github.com/charmbracelet/bubbletea` | v1.3.10 | MIT |
| `github.com/charmbracelet/lipgloss` | v1.1.0 | MIT |
| `github.com/charmbracelet/x/ansi` | v0.10.1 | MIT |
| `github.com/endobit/oui` | v0.7.0 | Apache-2.0 |
| `github.com/getsentry/sentry-go` | v0.46.2 | MIT |
| `github.com/go-playground/validator/v10` | v10.27.0 | MIT |
| `github.com/google/gopacket` | v1.1.19 | BSD-3-Clause |
| `github.com/google/nftables` | v0.3.0 | Apache-2.0 |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause |
| `github.com/mdlayher/netlink` | v1.8.0 | MIT |
| `github.com/mdlayher/wifi` | v0.7.2 | MIT |
| `github.com/oschwald/geoip2-golang` | v1.13.0 | ISC |
| `github.com/oschwald/maxminddb-golang` | v1.13.0 | ISC |
| `github.com/vishvananda/netlink` | v1.3.1 | Apache-2.0 |
| `golang.org/x/crypto` | v0.52.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.54.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.45.0 | BSD-3-Clause |
| `golang.zx2c4.com/wireguard/wgctrl` | v0.0.0-20241231184526-a9ab2273dd10 | MIT |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT |
| `modernc.org/sqlite` | v1.50.1 | BSD-3-Clause |

The Web UI vendors d3-sankey and a QR code library under
`internal/web/assets/vendor/`; see the README in that directory.
