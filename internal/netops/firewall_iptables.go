package netops

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// IptablesAvailable returns true iff the iptables binary is on PATH. The
// nftables backend is used by default - this one is a fallback for systems
// that still expose the legacy iptables ABI.
func IptablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// IptablesRule is one decoded row from `iptables -L -v -n -x`.
type IptablesRule struct {
	Chain   string
	Target  string
	Proto   string
	In      string
	Out     string
	Source  string
	Dest    string
	Packets uint64
	Bytes   uint64
	Extra   string
}

// IptablesSummary mirrors FirewallSummary's spirit for the legacy backend:
// a list of chains, each with its rules and the kernel-reported counters.
type IptablesSummary struct {
	Tables []IptablesTable
}

type IptablesTable struct {
	Name   string // "filter", "nat", "mangle"
	Chains []IptablesChain
}

type IptablesChain struct {
	Name    string
	Policy  string
	Packets uint64
	Bytes   uint64
	Rules   []IptablesRule
}

// ListIptables shells out to iptables for every standard table and parses
// the human-readable -v output (extended with -x for unscaled counters).
// Returns an empty summary - not an error - if the binary is missing.
func (w *Writer) ListIptables() (IptablesSummary, error) {
	if !IptablesAvailable() {
		return IptablesSummary{}, nil
	}
	out := IptablesSummary{}
	for _, table := range []string{"filter", "nat", "mangle"} {
		t, err := readIptablesTable(table)
		if err != nil {
			return out, fmt.Errorf("iptables -t %s: %w", table, err)
		}
		out.Tables = append(out.Tables, t)
	}
	return out, nil
}

func readIptablesTable(name string) (IptablesTable, error) {
	cmd := exec.Command("iptables", "-t", name, "-L", "-v", "-n", "-x")
	stdout, err := cmd.Output()
	if err != nil {
		return IptablesTable{Name: name}, err
	}
	return parseIptablesOutput(name, string(stdout)), nil
}

// parseIptablesOutput parses the canonical `iptables -L -v -n -x` format.
// The format is line-oriented:
//
//	Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
//	    pkts      bytes target     prot opt in     out     source       destination
//	       0         0 ACCEPT     tcp  --  *      *       0.0.0.0/0    0.0.0.0/0    tcp dpt:22
func parseIptablesOutput(table, raw string) IptablesTable {
	t := IptablesTable{Name: table}
	var current *IptablesChain
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "Chain ") {
			if current != nil {
				t.Chains = append(t.Chains, *current)
			}
			current = parseIptablesChainHeader(trim)
			continue
		}
		if strings.HasPrefix(trim, "pkts") {
			continue
		}
		if current == nil {
			continue
		}
		if rule, ok := parseIptablesRuleLine(current.Name, trim); ok {
			current.Rules = append(current.Rules, rule)
		}
	}
	if current != nil {
		t.Chains = append(t.Chains, *current)
	}
	return t
}

// parseIptablesChainHeader handles both built-in ("Chain INPUT (policy
// ACCEPT 0 packets, 0 bytes)") and user-defined ("Chain MYCHAIN (1
// references)") forms.
func parseIptablesChainHeader(line string) *IptablesChain {
	rest := strings.TrimPrefix(line, "Chain ")
	parenIdx := strings.IndexByte(rest, '(')
	if parenIdx < 0 {
		return &IptablesChain{Name: strings.TrimSpace(rest)}
	}
	name := strings.TrimSpace(rest[:parenIdx])
	body := strings.TrimSuffix(strings.TrimPrefix(rest[parenIdx:], "("), ")")
	c := &IptablesChain{Name: name}
	if strings.HasPrefix(body, "policy ") {
		fields := strings.Fields(body)
		// policy ACCEPT 0 packets, 0 bytes
		if len(fields) >= 2 {
			c.Policy = fields[1]
		}
		if len(fields) >= 3 {
			c.Packets, _ = strconv.ParseUint(fields[2], 10, 64)
		}
		if len(fields) >= 5 {
			c.Bytes, _ = strconv.ParseUint(fields[4], 10, 64)
		}
	}
	return c
}

func parseIptablesRuleLine(chain, line string) (IptablesRule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return IptablesRule{}, false
	}
	pkts, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return IptablesRule{}, false
	}
	bytes, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return IptablesRule{}, false
	}
	extra := ""
	if len(fields) > 8 {
		extra = strings.Join(fields[8:], " ")
	}
	return IptablesRule{
		Chain:   chain,
		Packets: pkts,
		Bytes:   bytes,
		Target:  fields[2],
		Proto:   fields[3],
		In:      fields[5],
		Out:     fields[6],
		Source:  fields[7],
		Dest:    safeField(fields, 8, "-"),
		Extra:   extra,
	}, true
}

func safeField(s []string, i int, def string) string {
	if i >= len(s) {
		return def
	}
	return s[i]
}
