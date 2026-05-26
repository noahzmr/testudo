# Firewall

Testudo ships with two firewall backends. Both are read-capable; writes
are gated by `netops.Writer.AllowWrites`.

| Backend   | Status               | Implementation                         |
| --------- | -------------------- | -------------------------------------- |
| iptables  | fallback (read-only) | `internal/netops/firewall_iptables.go` |
| nftables  | default              | `internal/netops/firewall.go`          |
| firewalld | roadmap              | -                                      |

## nftables (default)

Uses `github.com/google/nftables` over netlink. `Writer.ListFirewall`
enumerates tables and chains, returning hook, type, rule count, and
counter totals per chain.

Pros: native netlink, no shelling out, fine-grained counters.
Cons: requires recent kernel; some distributions still default to
iptables-nft compat mode.

## iptables (fallback)

Shells out to the `iptables` binary and parses `-L -v -n -x` output.
`Writer.ListIptables` returns the `filter`, `nat`, and `mangle` tables
with their chains, policies, and per-rule packet/byte counters.

`Writer.IptablesAvailable()` returns true iff the binary is on PATH. The
backend silently no-ops on systems without iptables installed - there's
no error, just an empty `IptablesSummary`. This makes it safe to call
unconditionally from the UI layer.

## Choosing a backend

The UI prefers nftables when available and falls back to iptables. On
distributions running iptables-nft compatibility (`iptables` is a symlink
to `iptables-nft`), both backends return overlapping data - that's a
distribution artefact, not a bug.

## Adding a backend (firewalld)

To add firewalld:

1. Create `internal/netops/firewall_firewalld.go`.
2. Talk to firewalld over D-Bus (suggested: `github.com/godbus/dbus/v5`).
3. Expose `Writer.ListFirewalld() (FirewalldSummary, error)`.
4. Update [docs/firewall.md](firewall.md) and `DEVELOPER.md`.
5. Wire the selector in the TUI / Web firewall tab.
