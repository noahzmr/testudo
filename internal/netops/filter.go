package netops

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// filterTableName is the private nftables table Testudo manages for
// user-added filter rules. Keeping a dedicated table means our adds/deletes
// can never collide with the operator's existing firewall ruleset.
const filterTableName = "testudo_filter"

// FilterRule is one accept/drop rule in our private nftables table.
//
// Every field except Chain and Action is optional — empty means "any".
// Chain is one of "input", "output", "forward".
// IP fields accept a bare address ("192.168.1.10") or a CIDR ("10.0.0.0/24")
// and are IPv4-only; setting them implicitly gates the rule on IPv4 packets.
type FilterRule struct {
	Chain    string // "input" / "output" / "forward"
	Action   string // "accept" / "drop"
	Proto    string // "" / "tcp" / "udp"
	Port     uint16 // 0 = any
	InIface  string // iifname (input / forward only)
	OutIface string // oifname (output / forward only)
	SrcCIDR  string // source IPv4 or CIDR
	DstCIDR  string // destination IPv4 or CIDR
}

// ruleKey is the UserData payload we attach to each rule so list+delete can
// round-trip the full FilterRule shape without trying to decode the nftables
// expression list (which gets fragile fast once IP / iface matches are in
// the mix).
func ruleKey(fr FilterRule) string {
	return strings.Join([]string{
		fr.Chain, fr.Action, fr.Proto, strconv.FormatUint(uint64(fr.Port), 10),
		fr.InIface, fr.OutIface, fr.SrcCIDR, fr.DstCIDR,
	}, "|")
}

func parseRuleKey(s string) (FilterRule, bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 8 {
		return FilterRule{}, false
	}
	port, _ := strconv.ParseUint(parts[3], 10, 16)
	return FilterRule{
		Chain:    parts[0],
		Action:   parts[1],
		Proto:    parts[2],
		Port:     uint16(port),
		InIface:  parts[4],
		OutIface: parts[5],
		SrcCIDR:  parts[6],
		DstCIDR:  parts[7],
	}, true
}

// AddFilterRule installs a filter rule in the testudo_filter table.
// Idempotency mirrors AddPortForward: callers wanting "replace" semantics
// should DelFilterRule first.
func (w *Writer) AddFilterRule(fr FilterRule) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	if err := validateFilterRule(fr); err != nil {
		return err
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   filterTableName,
	})
	hook := nftables.ChainHookInput
	switch fr.Chain {
	case "output":
		hook = nftables.ChainHookOutput
	case "forward":
		hook = nftables.ChainHookForward
	}
	priority := nftables.ChainPriorityFilter
	chain := conn.AddChain(&nftables.Chain{
		Name:     fr.Chain,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: priority,
	})

	exprs, err := buildFilterExprs(fr)
	if err != nil {
		return err
	}

	rule := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(ruleKey(fr)),
	}
	conn.AddRule(rule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush nft: %w", err)
	}
	return nil
}

// DelFilterRule removes the rule that matches the given target exactly.
// The chain/proto/port-only signature is kept by zeroing the new fields —
// callers that don't care about iface/IP can leave them empty and the
// matching is done on Chain + Action + Proto + Port. Pass a fully-populated
// FilterRule for surgical deletion.
func (w *Writer) DelFilterRule(target FilterRule) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	var ours *nftables.Table
	for _, t := range tables {
		if t.Name == filterTableName && t.Family == nftables.TableFamilyINet {
			ours = t
			break
		}
	}
	if ours == nil {
		return nil
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	for _, c := range chains {
		if c.Table.Name != ours.Name || c.Table.Family != ours.Family {
			continue
		}
		if target.Chain != "" && c.Name != target.Chain {
			continue
		}
		rules, err := conn.GetRules(ours, c)
		if err != nil {
			continue
		}
		for _, r := range rules {
			fr, ok := decodeRuleUserData(r)
			if !ok {
				// Legacy rules without UserData — fall back to expr decode.
				fr, ok = decodeFilterRule(r)
				fr.Chain = c.Name
			}
			if !ok {
				continue
			}
			if matchesTarget(fr, target) {
				_ = conn.DelRule(r)
			}
		}
	}
	return conn.Flush()
}

// matchesTarget returns true when every non-empty field of target equals
// the corresponding field of fr. Empty fields in target act as wildcards.
func matchesTarget(fr, target FilterRule) bool {
	if target.Chain != "" && fr.Chain != target.Chain {
		return false
	}
	if target.Action != "" && fr.Action != target.Action {
		return false
	}
	if target.Proto != "" && fr.Proto != target.Proto {
		return false
	}
	if target.Port != 0 && fr.Port != target.Port {
		return false
	}
	if target.InIface != "" && fr.InIface != target.InIface {
		return false
	}
	if target.OutIface != "" && fr.OutIface != target.OutIface {
		return false
	}
	if target.SrcCIDR != "" && fr.SrcCIDR != target.SrcCIDR {
		return false
	}
	if target.DstCIDR != "" && fr.DstCIDR != target.DstCIDR {
		return false
	}
	return true
}

// ListFilterRules returns every rule currently in our private filter table.
// Returns nil (not an error) when the table doesn't exist yet.
func (w *Writer) ListFilterRules() ([]FilterRule, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	var ours *nftables.Table
	for _, t := range tables {
		if t.Name == filterTableName && t.Family == nftables.TableFamilyINet {
			ours = t
			break
		}
	}
	if ours == nil {
		return nil, nil
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	var out []FilterRule
	for _, c := range chains {
		if c.Table.Name != ours.Name || c.Table.Family != ours.Family {
			continue
		}
		rules, err := conn.GetRules(ours, c)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if fr, ok := decodeRuleUserData(r); ok {
				out = append(out, fr)
				continue
			}
			// Legacy rules: best-effort decode from expressions.
			if fr, ok := decodeFilterRule(r); ok {
				fr.Chain = c.Name
				out = append(out, fr)
			}
		}
	}
	return out, nil
}

func decodeRuleUserData(r *nftables.Rule) (FilterRule, bool) {
	if len(r.UserData) == 0 {
		return FilterRule{}, false
	}
	return parseRuleKey(string(r.UserData))
}

// validateFilterRule guards against obviously-wrong combinations before we
// touch netlink.
func validateFilterRule(fr FilterRule) error {
	switch fr.Chain {
	case "input", "output", "forward":
	default:
		return fmt.Errorf("chain must be input / output / forward, got %q", fr.Chain)
	}
	switch fr.Action {
	case "accept", "drop":
	default:
		return fmt.Errorf("action must be accept or drop, got %q", fr.Action)
	}
	if fr.Proto != "" && fr.Proto != "tcp" && fr.Proto != "udp" {
		return fmt.Errorf("proto must be tcp / udp / empty, got %q", fr.Proto)
	}
	if fr.Port != 0 && fr.Proto == "" {
		return fmt.Errorf("port requires a proto (tcp or udp)")
	}
	if fr.InIface != "" && fr.Chain == "output" {
		return fmt.Errorf("in_iface has no effect on the output chain")
	}
	if fr.OutIface != "" && fr.Chain == "input" {
		return fmt.Errorf("out_iface has no effect on the input chain")
	}
	if fr.SrcCIDR != "" {
		if _, _, err := parseCIDROrIP(fr.SrcCIDR); err != nil {
			return fmt.Errorf("src: %w", err)
		}
	}
	if fr.DstCIDR != "" {
		if _, _, err := parseCIDROrIP(fr.DstCIDR); err != nil {
			return fmt.Errorf("dst: %w", err)
		}
	}
	return nil
}

// buildFilterExprs assembles the nftables expressions that implement fr.
// Order matters: IPv4 family gate first (if IP fields are set), then iface
// matches, then IP matches, then proto + port, then verdict last.
func buildFilterExprs(fr FilterRule) ([]expr.Any, error) {
	var exprs []expr.Any

	if fr.SrcCIDR != "" || fr.DstCIDR != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		)
	}
	if fr.InIface != "" {
		exprs = append(exprs, ifaceMatchExprs(expr.MetaKeyIIFNAME, fr.InIface)...)
	}
	if fr.OutIface != "" {
		exprs = append(exprs, ifaceMatchExprs(expr.MetaKeyOIFNAME, fr.OutIface)...)
	}
	if fr.SrcCIDR != "" {
		m, err := ipv4MatchExprs(12, fr.SrcCIDR)
		if err != nil {
			return nil, fmt.Errorf("src: %w", err)
		}
		exprs = append(exprs, m...)
	}
	if fr.DstCIDR != "" {
		m, err := ipv4MatchExprs(16, fr.DstCIDR)
		if err != nil {
			return nil, fmt.Errorf("dst: %w", err)
		}
		exprs = append(exprs, m...)
	}
	if fr.Proto != "" {
		proto := byte(6) // tcp
		if fr.Proto == "udp" {
			proto = 17
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
	}
	if fr.Port != 0 {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1, Base: expr.PayloadBaseTransportHeader,
				Offset: 2, Len: 2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(fr.Port)},
		)
	}
	verdict := expr.VerdictAccept
	if fr.Action == "drop" {
		verdict = expr.VerdictDrop
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdict})
	return exprs, nil
}

// ifaceMatchExprs returns the nftables expressions that compare iifname or
// oifname (depending on key) to a 16-byte zero-padded name buffer.
func ifaceMatchExprs(key expr.MetaKey, name string) []expr.Any {
	buf := make([]byte, 16)
	copy(buf, []byte(name))
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: buf},
	}
}

// ipv4MatchExprs returns the expressions that match an IPv4 source/dest
// address at the given network-header offset. For CIDR inputs it inserts a
// Bitwise mask between the Payload load and the Cmp.
func ipv4MatchExprs(offset uint32, addr string) ([]expr.Any, error) {
	ip, mask, err := parseCIDROrIP(addr)
	if err != nil {
		return nil, err
	}
	out := []expr.Any{
		&expr.Payload{
			DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
			Offset: offset, Len: 4,
		},
	}
	if mask != nil {
		out = append(out, &expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: mask, Xor: []byte{0, 0, 0, 0},
		})
	}
	out = append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip})
	return out, nil
}

func parseCIDROrIP(s string) (ip []byte, mask []byte, err error) {
	if strings.Contains(s, "/") {
		_, ipnet, perr := net.ParseCIDR(s)
		if perr != nil {
			return nil, nil, perr
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			return nil, nil, fmt.Errorf("not IPv4: %s", s)
		}
		return []byte(ip4), []byte(ipnet.Mask), nil
	}
	raw := net.ParseIP(s)
	if raw == nil {
		return nil, nil, fmt.Errorf("not IPv4: %s", s)
	}
	ip4 := raw.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("not IPv4: %s", s)
	}
	return []byte(ip4), nil, nil
}

// decodeFilterRule is kept as a best-effort fallback for legacy rules added
// before we started writing UserData. It populates only proto / port /
// action; the new fields stay empty.
func decodeFilterRule(r *nftables.Rule) (FilterRule, bool) {
	var fr FilterRule
	var sawProto, sawPort, sawVerdict bool
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Cmp:
			if v.Op == expr.CmpOpEq && len(v.Data) == 1 {
				switch v.Data[0] {
				case 6:
					fr.Proto = "tcp"
					sawProto = true
				case 17:
					fr.Proto = "udp"
					sawProto = true
				}
			}
			if v.Op == expr.CmpOpEq && len(v.Data) == 2 {
				fr.Port = uint16(v.Data[0])<<8 | uint16(v.Data[1])
				sawPort = true
			}
		case *expr.Verdict:
			switch v.Kind {
			case expr.VerdictAccept:
				fr.Action = "accept"
				sawVerdict = true
			case expr.VerdictDrop:
				fr.Action = "drop"
				sawVerdict = true
			}
		}
	}
	if sawProto && sawPort && sawVerdict {
		return fr, true
	}
	return FilterRule{}, false
}
