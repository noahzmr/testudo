# Task 01 — Per-Rule nftables Counters

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment:

> **Firewall debugging — Partial.** nft + iptables enumeration, chain-level
> counters. **No per-rule hit counters**, no policy display, no rule decode, no
> log target.

And the prioritized roadmap:

> **Per-rule nftables counters** (add `expr.Counter`) — small change, big
> firewall-debug payoff — turns the firewall view from "chain totals" into
> "which rule fired."

This is the cheapest high-value firewall win: when "only some services work",
the operator needs to see *which rule* is dropping traffic, not just that a
chain dropped something.

## Current state

[`internal/netops/firewall.go`](../../internal/netops/firewall.go) today:

- `ListFirewall() (FirewallSummary, error)` reads tables/chains via
  `nftables.New()` + `conn.ListTables()` / `conn.ListChains()`.
- For each chain it sums packet/byte counters into `ChainInfo{Packets, Bytes}`.
- It does **not** add `expr.Counter` to rules, nor read per-rule handles, nor
  decode rule expressions into a human verdict.

`ChainInfo` carries chain-level totals only. The Firewall tab (TUI + Web) shows
per-chain aggregates.

## Goals

- A `RuleInfo` model with: handle, chain, family, decoded match (proto, saddr,
  daddr, sport, dport, iif/oif), verdict (ACCEPT/DROP/REJECT/JUMP/LOG/RETURN),
  and **per-rule `Packets`/`Bytes` counters**.
- When Testudo *creates* a rule (writes enabled), attach an `expr.Counter` so
  the rule is countable; expose a way to **reset** a rule's counter.
- Decode existing rules' expressions well enough to render a one-line summary.
- Surface per-rule counters and verdicts in both UIs, with the highest-hit
  DROP/REJECT rules sorted to the top (the "what's blocking me" view).

## Non-goals

- iptables per-rule counters beyond what `iptables -L -v -n -x` already gives
  (read-only; the nftables path is the managed one).
- Rewriting the existing chain-level summary — extend, don't replace.

## Design

In [`internal/netops/firewall.go`](../../internal/netops/firewall.go):

```go
// RuleInfo is one decoded firewall rule with live counters.
type RuleInfo struct {
    Family   string // ip / ip6 / inet
    Table    string
    Chain    string
    Handle   uint64 // nftables rule handle (stable id for reset/delete)
    Match    string // decoded: "tcp dport 22 iif eth0"
    Verdict  string // ACCEPT / DROP / REJECT / LOG / JUMP <chain> / RETURN
    Comment  string // nft comment expr, if present
    Packets  uint64
    Bytes    uint64
    HasCounter bool // false = rule predates counter attachment
}

func (w *Writer) ListFirewallRules() ([]RuleInfo, error)
func (w *Writer) ResetRuleCounter(family, table, chain string, handle uint64) error // write-gated
```

- `ListFirewallRules` walks `conn.GetRules(table, chain)` and decodes the
  `[]expr.Any` statement list: `expr.Meta`/`expr.Cmp`/`expr.Payload` →
  match string; `expr.Counter` → `Packets`/`Bytes`+`HasCounter=true`;
  `expr.Verdict`/`expr.Log` → verdict.
- Rule **creation** (existing add-rule modal path) gains an `expr.Counter{}`
  expression so every Testudo-managed rule is born countable.
- `ResetRuleCounter` replaces the rule's counter expr (nftables has no in-place
  counter zero; delete+re-add the rule by handle, preserving position) — gated
  by `Writer.AllowWrites`, same as every other mutation.
- Decoding lives in a pure helper `decodeRule([]expr.Any) (match, verdict string)`
  so it is unit-testable without a live kernel.

## TUI

Firewall tab ([`internal/tui/`](../../internal/tui/)):

- Expand each chain into its rules. Columns: `HANDLE · MATCH · VERDICT · PKTS · BYTES`.
- DROP/REJECT rules with the highest packet counts float to the top of their
  chain (the diagnostic ordering).
- A rule with `HasCounter=false` renders `pkts/bytes` as `—` with a hint
  ("legacy rule — recreate via Testudo to enable counting").
- **Edit affordance:** keybinding on a selected rule opens the existing
  add/remove rule modal pre-filled; an `r` action calls `ResetRuleCounter`
  (only when netops writes are enabled, otherwise the action is greyed with the
  standard `ErrWritesDisabled` toast).

## Web UI

Firewall view ([`internal/web/`](../../internal/web/)):

- Same per-rule table, same top-sorted DROP rows.
- The rule modal (already used for add/remove) gains a "Reset counter" button
  on existing rules. Mutating endpoints reuse the existing netops-write auth gate.
- JSON snapshot endpoint exposes `[]RuleInfo` so the web table and any external
  consumer see identical data to the TUI.

## Network Quality

Per-rule DROP/REJECT velocity is a real degradation signal. Contribution:

- Feed the **rate of growth of DROP/REJECT packet counters** into a new
  **firewall-interference** input. A sudden spike of drops against an active
  flow is a connectivity problem the user *feels* ("only some services work").
- Fold this into the existing grade via a small **Firewall** signal (suggest
  5% weight, rebalanced from the WAN/HTTP headroom), or — minimally — let it
  influence the **Stab** sub-score, since a flapping firewall is a stability
  fault. Neutral 100 when no managed DROP rules exist.
- Emit a `KindFirewallDrop` anomaly (already in the severity ladder) keyed by
  rule handle so the Alerts tab names the exact rule.

## Storage / replay

- Persist a periodic per-rule counter sample to a new `firewall_rule_samples`
  table (`ts, family, table, chain, handle, pkts, bytes`) so replay can show
  "which rule's drops climbed during the incident". Reuse the downsampling path.
- Counter deltas travel the event bus as `KindFirewallDrop` events.

## Reliability & security

- Read path needs no extra privilege (nftables read works unprivileged on most
  kernels; soft-fail per-table like the existing code).
- Counter reset and rule creation stay behind `--allow-netops-write`; log every
  mutation (handle + before/after) toward the audit-log gap the assessment
  flags under Security concerns.

## Testing

- Unit-test `decodeRule` against captured `[]expr.Any` fixtures for: tcp dport
  drop, iif accept, jump, reject-with-icmp, log, comment. Pure function — no
  kernel.
- Unit-test the top-sort ordering and the `HasCounter=false` rendering branch.
- Integration test behind a build tag that creates a temp table in a netns.

## Acceptance criteria

- [ ] `ListFirewallRules` returns decoded rules with per-rule pkts/bytes.
- [ ] Testudo-created rules carry an `expr.Counter`.
- [ ] Counter reset works and is write-gated + audit-logged.
- [ ] TUI Firewall tab shows per-rule counters, top-sorted DROPs, edit+reset modals.
- [ ] Web Firewall view has identical data and the reset/edit affordances.
- [ ] DROP-rate feeds the Network Quality grade; documented in README grade table.
- [ ] Per-rule samples persist and replay.
- [ ] `decodeRule` unit tests pass; `go vet` clean.
