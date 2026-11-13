package netops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	natTableName = "testudo_nat"
	// legacyMasqTableName is where pre-policy builds kept masquerade rules.
	// ApplyNATTable removes it (its rules are imported into the policy first).
	legacyMasqTableName = "testudo_masq"
)

// PortForward describes a destination-NAT rule managed by Testudo: traffic
// arriving on WANPort (optionally only via InIface) is rewritten to
// LANIP:LANPort. IPv4 only.
type PortForward struct {
	Proto   string `json:"proto"`              // "tcp" or "udp"
	WANPort uint16 `json:"wan_port"`           // port reachable from the outside
	LANIP   string `json:"lan_ip"`             // internal target IP
	LANPort uint16 `json:"lan_port"`           // internal target port (defaults to WANPort if 0)
	InIface string `json:"in_iface,omitempty"` // restrict to this ingress interface; "" = any
	Comment string `json:"comment,omitempty"`
	Owner   string `json:"owner,omitempty"`
}

// Normalize returns the canonical form (lower-cased proto, defaulted LAN port
// and owner). ID is computed over it.
func (pf PortForward) Normalize() PortForward {
	n := pf
	n.Proto = strings.ToLower(strings.TrimSpace(n.Proto))
	n.LANIP = strings.TrimSpace(n.LANIP)
	if ip := net.ParseIP(n.LANIP); ip != nil {
		n.LANIP = ip.String()
	}
	if n.LANPort == 0 {
		n.LANPort = n.WANPort
	}
	n.InIface = strings.TrimSpace(n.InIface)
	n.Comment = strings.TrimSpace(n.Comment)
	n.Owner = strings.TrimSpace(n.Owner)
	if n.Owner == "" {
		n.Owner = OwnerUser
	}
	return n
}

// Validate guards the forward before anything touches netlink.
func (pf PortForward) Validate() error {
	n := pf.Normalize()
	if n.Proto != "tcp" && n.Proto != "udp" {
		return fmt.Errorf("proto must be tcp or udp, got %q", pf.Proto)
	}
	if n.WANPort == 0 {
		return fmt.Errorf("wan_port is required")
	}
	lan := net.ParseIP(n.LANIP)
	if lan == nil || lan.To4() == nil {
		return fmt.Errorf("lan ip must be IPv4, got %q", pf.LANIP)
	}
	if len(n.InIface) > 15 {
		return fmt.Errorf("interface names are at most 15 characters")
	}
	if len(n.Comment) > 200 {
		return fmt.Errorf("comment is at most 200 characters")
	}
	return nil
}

// ID is a stable content hash of the normalized forward (12 hex chars).
func (pf PortForward) ID() string {
	n := pf.Normalize()
	h := sha256.Sum256([]byte(strings.Join([]string{
		tagForward, n.Proto, strconv.Itoa(int(n.WANPort)), n.LANIP,
		strconv.Itoa(int(n.LANPort)), n.InIface, n.Owner,
	}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// String renders the forward nft-style.
func (pf PortForward) String() string {
	n := pf.Normalize()
	var b strings.Builder
	b.WriteString("prerouting")
	if n.InIface != "" {
		b.WriteString(" iifname " + n.InIface)
	}
	fmt.Fprintf(&b, " %s dport %d dnat to %s:%d", n.Proto, n.WANPort, n.LANIP, n.LANPort)
	return b.String()
}

// Masquerade is a source-NAT rule: packets from SrcCIDR leaving via OutIface
// are rewritten to the interface's address. Used by the WireGuard full-tunnel
// preset and by operators sharing a WAN uplink. IPv4 only.
type Masquerade struct {
	OutIface string `json:"out_iface"`
	SrcCIDR  string `json:"src"`
	Comment  string `json:"comment,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

// Normalize returns the canonical form (network-address CIDR, defaulted owner).
func (m Masquerade) Normalize() Masquerade {
	n := m
	n.OutIface = strings.TrimSpace(n.OutIface)
	n.SrcCIDR = canonicalCIDR(n.SrcCIDR)
	n.Comment = strings.TrimSpace(n.Comment)
	n.Owner = strings.TrimSpace(n.Owner)
	if n.Owner == "" {
		n.Owner = OwnerUser
	}
	return n
}

// Validate guards the masquerade before anything touches netlink.
func (m Masquerade) Validate() error {
	n := m.Normalize()
	if n.OutIface == "" {
		return fmt.Errorf("masquerade out interface required")
	}
	if len(n.OutIface) > 15 {
		return fmt.Errorf("interface names are at most 15 characters")
	}
	ip, _, err := parseCIDROrIP(n.SrcCIDR)
	if err != nil {
		return fmt.Errorf("masquerade src: %w", err)
	}
	if len(ip) != net.IPv4len {
		return fmt.Errorf("masquerade src must be IPv4")
	}
	if len(n.Comment) > 200 {
		return fmt.Errorf("comment is at most 200 characters")
	}
	return nil
}

// ID is a stable content hash of the normalized masquerade (12 hex chars).
func (m Masquerade) ID() string {
	n := m.Normalize()
	h := sha256.Sum256([]byte(strings.Join([]string{tagMasquerade, n.SrcCIDR, n.OutIface, n.Owner}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// String renders the masquerade nft-style.
func (m Masquerade) String() string {
	n := m.Normalize()
	return fmt.Sprintf("postrouting ip saddr %s oifname %s masquerade", n.SrcCIDR, n.OutIface)
}

// NATSpec is the complete desired content of the testudo_nat table.
type NATSpec struct {
	Forwards    []PortForward `json:"forwards"`
	Masquerades []Masquerade  `json:"masquerades"`
}

// ApplyNATTable replaces the whole testudo_nat table (DNAT prerouting +
// masquerade postrouting) with spec in one atomic netlink batch, and removes
// the legacy testudo_masq table if present. Write-gated.
func (w *Writer) ApplyNATTable(spec NATSpec) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.mutate(Op{Kind: OpApplyNATTable, NATSpec: &spec})
}

func (w *Writer) applyNATTableDirect(spec NATSpec) error {
	fwdExprs := make([][]expr.Any, len(spec.Forwards))
	for i, pf := range spec.Forwards {
		if err := pf.Validate(); err != nil {
			return fmt.Errorf("forward %d (%s): %w", i, pf, err)
		}
		fwdExprs[i] = buildForwardExprs(pf.Normalize())
	}
	masqExprs := make([][]expr.Any, len(spec.Masquerades))
	for i, m := range spec.Masquerades {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("masquerade %d (%s): %w", i, m, err)
		}
		ex, err := buildMasqueradeExprs(m.Normalize())
		if err != nil {
			return fmt.Errorf("masquerade %d (%s): %w", i, m, err)
		}
		masqExprs[i] = ex
	}

	conn, err := nftConn()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	for _, name := range []string{natTableName, legacyMasqTableName} {
		old, err := findTable(conn, nftables.TableFamilyIPv4, name)
		if err != nil {
			return err
		}
		if old != nil {
			conn.DelTable(old)
		}
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: natTableName})
	accept := nftables.ChainPolicyAccept
	pre := conn.AddChain(&nftables.Chain{
		Name: "prerouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept,
	})
	post := conn.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept,
	})
	for i, pf := range spec.Forwards {
		n := pf.Normalize()
		conn.AddRule(&nftables.Rule{Table: table, Chain: pre, Exprs: fwdExprs[i],
			UserData: managedUserData(tagForward, n.ID(), n.Comment)})
	}
	for i, m := range spec.Masquerades {
		n := m.Normalize()
		conn.AddRule(&nftables.Rule{Table: table, Chain: post, Exprs: masqExprs[i],
			UserData: managedUserData(tagMasquerade, n.ID(), n.Comment)})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply nat table: %w", err)
	}
	return nil
}

// buildForwardExprs compiles a DNAT rule for the ip family.
func buildForwardExprs(pf PortForward) []expr.Any {
	var exprs []expr.Any
	if pf.InIface != "" {
		exprs = append(exprs, ifaceMatchExprs(expr.MetaKeyIIFNAME, pf.InIface)...)
	}
	proto := byte(unix.IPPROTO_TCP)
	if pf.Proto == "udp" {
		proto = unix.IPPROTO_UDP
	}
	lan := net.ParseIP(pf.LANIP).To4()
	exprs = append(exprs,
		// ip protocol == tcp|udp
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		// th dport == WANPort
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(pf.WANPort)},
		&expr.Counter{},
		// dnat to LANIP:LANPort
		&expr.Immediate{Register: 1, Data: lan},
		&expr.Immediate{Register: 2, Data: be16(pf.LANPort)},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(nftables.TableFamilyIPv4), RegAddrMin: 1, RegProtoMin: 2},
	)
	return exprs
}

// buildMasqueradeExprs compiles a masquerade rule for the ip family.
func buildMasqueradeExprs(m Masquerade) ([]expr.Any, error) {
	saddr, err := addrMatchExprs(true, m.SrcCIDR)
	if err != nil {
		return nil, err
	}
	exprs := append([]expr.Any{}, saddr...)
	exprs = append(exprs, ifaceMatchExprs(expr.MetaKeyOIFNAME, m.OutIface)...)
	exprs = append(exprs, &expr.Counter{}, &expr.Masq{})
	return exprs, nil
}

// ManagedForward is a DNAT rule as it exists in the kernel, decoded from its
// expressions, with the ID it was installed with (empty for legacy rules).
type ManagedForward struct {
	PortForward
	ID         string `json:"id"`
	Handle     uint64 `json:"handle"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
	Legacy     bool   `json:"legacy,omitempty"`
}

// ManagedMasquerade is a masquerade rule as it exists in the kernel.
type ManagedMasquerade struct {
	Masquerade
	ID         string `json:"id"`
	Handle     uint64 `json:"handle"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
	Legacy     bool   `json:"legacy,omitempty"`
}

// NATTableState is the live kernel view of Testudo's NAT rules: the
// testudo_nat table plus anything still sitting in the legacy testudo_masq
// table (reported with Legacy=true so it can be imported, then removed).
type NATTableState struct {
	Exists          bool                `json:"exists"`
	LegacyMasqTable bool                `json:"legacy_masq_table,omitempty"`
	Forwards        []ManagedForward    `json:"forwards"`
	Masquerades     []ManagedMasquerade `json:"masquerades"`
}

// NATTableState reads the live NAT tables. Exists=false (no error) when the
// testudo_nat table has not been created yet. Privileged read via the query
// seam (see FilterTableState).
func (w *Writer) NATTableState() (NATTableState, error) {
	var out NATTableState
	err := w.queryInto(Op{Kind: OpQueryNATState}, &out)
	return out, err
}

func (w *Writer) natTableStateDirect() (NATTableState, error) {
	conn, err := nftConn()
	if err != nil {
		return NATTableState{}, fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	var st NATTableState
	chains, err := conn.ListChains()
	if err != nil {
		return st, err
	}
	ours, err := findTable(conn, nftables.TableFamilyIPv4, natTableName)
	if err != nil {
		return st, err
	}
	if ours != nil {
		st.Exists = true
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
					mf := ManagedForward{PortForward: pf, Handle: r.Handle}
					mf.Packets, mf.Bytes, mf.HasCounter = ruleCounter(r.Exprs)
					if tag, id, _, ok := parseManagedUserData(r.UserData); ok && tag == tagForward {
						mf.ID = id
					} else {
						mf.Legacy = true
					}
					st.Forwards = append(st.Forwards, mf)
					continue
				}
				if m, ok := decodeMasquerade(r); ok {
					st.Masquerades = append(st.Masquerades, managedMasq(m, r, false))
				}
			}
		}
	}
	legacy, err := findTable(conn, nftables.TableFamilyIPv4, legacyMasqTableName)
	if err != nil {
		return st, err
	}
	if legacy != nil {
		st.LegacyMasqTable = true
		for _, c := range chains {
			if c.Table.Name != legacy.Name || c.Table.Family != legacy.Family {
				continue
			}
			rules, err := conn.GetRules(legacy, c)
			if err != nil {
				continue
			}
			for _, r := range rules {
				if m, ok := decodeMasquerade(r); ok {
					st.Masquerades = append(st.Masquerades, managedMasq(m, r, true))
				}
			}
		}
	}
	return st, nil
}

func managedMasq(m Masquerade, r *nftables.Rule, legacyTable bool) ManagedMasquerade {
	mm := ManagedMasquerade{Masquerade: m, Handle: r.Handle, Legacy: legacyTable}
	mm.Packets, mm.Bytes, mm.HasCounter = ruleCounter(r.Exprs)
	if tag, id, _, ok := parseManagedUserData(r.UserData); ok && tag == tagMasquerade {
		mm.ID = id
	} else {
		mm.Legacy = true
	}
	return mm
}

// ListPortForwards returns the DNAT rules currently in the kernel. Kept as a
// convenience for read-only callers; mutations go through the policy manager.
func (w *Writer) ListPortForwards() ([]PortForward, error) {
	st, err := w.NATTableState()
	if err != nil {
		return nil, err
	}
	out := make([]PortForward, 0, len(st.Forwards))
	for _, f := range st.Forwards {
		out = append(out, f.PortForward)
	}
	return out, nil
}

// decodePortForward recovers a PortForward from a DNAT rule's expressions.
func decodePortForward(r *nftables.Rule) (PortForward, bool) {
	var pf PortForward
	var sawProto, sawPort, sawNAT bool
	var metaKey expr.MetaKey
	var haveMeta bool
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Meta:
			metaKey, haveMeta = v.Key, true
		case *expr.Payload:
			haveMeta = false
		case *expr.Cmp:
			if haveMeta && metaKey == expr.MetaKeyIIFNAME && len(v.Data) == 16 {
				pf.InIface = trimIface(v.Data)
				haveMeta = false
				continue
			}
			haveMeta = false
			if v.Op == expr.CmpOpEq && len(v.Data) == 1 {
				switch v.Data[0] {
				case unix.IPPROTO_TCP:
					pf.Proto, sawProto = "tcp", true
				case unix.IPPROTO_UDP:
					pf.Proto, sawProto = "udp", true
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

// decodeMasquerade recovers a Masquerade from a rule's expressions (saddr
// payload + optional mask, oifname, masq).
func decodeMasquerade(r *nftables.Rule) (Masquerade, bool) {
	var m Masquerade
	var sawMasq bool
	var (
		pending     string // "saddr" / "oif"
		mask        []byte
		metaKey     expr.MetaKey
		havePayload bool
	)
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Payload:
			havePayload = v.Base == expr.PayloadBaseNetworkHeader && v.Offset == 12 && v.Len == 4
			pending, mask = "", nil
			if havePayload {
				pending = "saddr"
			}
		case *expr.Bitwise:
			if pending == "saddr" {
				mask = v.Mask
			}
		case *expr.Meta:
			metaKey = v.Key
			pending = ""
			if metaKey == expr.MetaKeyOIFNAME {
				pending = "oif"
			}
		case *expr.Cmp:
			switch pending {
			case "saddr":
				if len(v.Data) == 4 {
					m.SrcCIDR = ipMaskString(v.Data, mask)
				}
			case "oif":
				if len(v.Data) == 16 {
					m.OutIface = trimIface(v.Data)
				}
			}
			pending, mask = "", nil
		case *expr.Masq:
			sawMasq = true
		}
	}
	if sawMasq && m.OutIface != "" && m.SrcCIDR != "" {
		return m.Normalize(), true
	}
	return Masquerade{}, false
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
