package netops

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const natTableName = "testudo_nat"

// PortForward describes a destination-NAT rule managed by Testudo.
type PortForward struct {
	Proto     string // "tcp" or "udp"
	WANPort   uint16 // port reachable from the outside
	LANIP     string // internal target IP
	LANPort   uint16 // internal target port (defaults to WANPort if 0)
	Comment   string
}

// AddPortForward installs a DNAT rule in our private nftables table.
// Idempotency: re-running with the same params yields a duplicate rule;
// callers wanting idempotent semantics should call DelPortForward first.
func (w *Writer) AddPortForward(pf PortForward) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	if pf.Proto != "tcp" && pf.Proto != "udp" {
		return fmt.Errorf("proto must be tcp or udp, got %q", pf.Proto)
	}
	lan := net.ParseIP(pf.LANIP)
	if lan == nil || lan.To4() == nil {
		return fmt.Errorf("lan ip must be IPv4, got %q", pf.LANIP)
	}
	if pf.LANPort == 0 {
		pf.LANPort = pf.WANPort
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	// Ensure our private table and a single PREROUTING chain exist.
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   natTableName,
	})
	hook := nftables.ChainHookPrerouting
	priority := nftables.ChainPriorityNATDest
	chain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  hook,
		Priority: priority,
	})

	protoMatch := byte(6) // tcp
	if pf.Proto == "udp" {
		protoMatch = 17
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// L4 proto match (ip protocol == tcp|udp)
			&expr.Payload{
				DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
				Offset: 9, Len: 1,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoMatch}},
			// dport match
			&expr.Payload{
				DestRegister: 1, Base: expr.PayloadBaseTransportHeader,
				Offset: 2, Len: 2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(pf.WANPort)},
			// dnat to LAN:LAN_PORT
			&expr.Immediate{Register: 1, Data: lan.To4()},
			&expr.Immediate{Register: 2, Data: be16(pf.LANPort)},
			&expr.NAT{
				Type: expr.NATTypeDestNAT, Family: uint32(nftables.TableFamilyIPv4),
				RegAddrMin: 1, RegProtoMin: 2,
			},
		},
	}
	conn.AddRule(rule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush nft: %w", err)
	}
	return nil
}

// DelPortForward removes ALL rules in our private table that match the
// given proto + wan port. Coarse-grained but predictable.
func (w *Writer) DelPortForward(proto string, wanPort uint16) error {
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
		if t.Name == natTableName && t.Family == nftables.TableFamilyIPv4 {
			ours = t
			break
		}
	}
	if ours == nil {
		return errors.New("no testudo_nat table installed")
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	for _, c := range chains {
		if c.Table.Name != ours.Name || c.Table.Family != ours.Family {
			continue
		}
		rules, err := conn.GetRules(ours, c)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if ruleMatchesForward(r, proto, wanPort) {
				_ = conn.DelRule(r)
			}
		}
	}
	return conn.Flush()
}

// ListPortForwards returns DNAT rules in our private table.
func (w *Writer) ListPortForwards() ([]PortForward, error) {
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
		if t.Name == natTableName && t.Family == nftables.TableFamilyIPv4 {
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
	var out []PortForward
	for _, c := range chains {
		if c.Table.Name != ours.Name || c.Table.Family != ours.Family {
			continue
		}
		rules, err := conn.GetRules(ours, c)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if pf, ok := decodePortForward(r); ok {
				out = append(out, pf)
			}
		}
	}
	return out, nil
}

func ruleMatchesForward(r *nftables.Rule, proto string, wanPort uint16) bool {
	pf, ok := decodePortForward(r)
	if !ok {
		return false
	}
	return pf.Proto == proto && pf.WANPort == wanPort
}

func decodePortForward(r *nftables.Rule) (PortForward, bool) {
	var pf PortForward
	var sawProto, sawPort, sawNAT bool
	for i, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Cmp:
			if v.Op == expr.CmpOpEq && len(v.Data) == 1 && i > 0 {
				switch v.Data[0] {
				case 6:
					pf.Proto = "tcp"
					sawProto = true
				case 17:
					pf.Proto = "udp"
					sawProto = true
				}
			}
			if v.Op == expr.CmpOpEq && len(v.Data) == 2 {
				pf.WANPort = uint16(v.Data[0])<<8 | uint16(v.Data[1])
				sawPort = true
			}
		case *expr.Immediate:
			if len(v.Data) == 4 {
				pf.LANIP = net.IP(v.Data).String()
			}
			if len(v.Data) == 2 {
				pf.LANPort = uint16(v.Data[0])<<8 | uint16(v.Data[1])
			}
		case *expr.NAT:
			if v.Type == expr.NATTypeDestNAT {
				sawNAT = true
			}
		}
	}
	if sawProto && sawPort && sawNAT && pf.LANIP != "" {
		return pf, true
	}
	return PortForward{}, false
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
