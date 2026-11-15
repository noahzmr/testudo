package lbrender

import (
	"sort"
	"strconv"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Hint says which filter rule a service needs so that clients can reach it.
// A hint is a proposal: nothing opens the packet filter until a person
// creates the rule.
type Hint struct {
	Service string `json:"service"` // model id
	Name    string `json:"name"`
	// Covered is true when an enabled rule already accepts the traffic.
	Covered bool `json:"covered"`
	// Rule is the filter rule to create when it is not.
	Rule *model.FilterRule `json:"rule,omitempty"`
}

// FirewallHints proposes one inbound rule per enabled proxy-mode service.
// Services balanced in the packet filter need none: a connection the
// packet filter translated is forwarded by the same ruleset.
func FirewallHints(st *confstore.State) []Hint {
	var rules []*model.FilterRule
	for _, e := range st.List(model.KindFilterRule) {
		if r := e.(*model.FilterRule); r.Enabled && r.Action == "accept" && r.Direction == "in" {
			rules = append(rules, r)
		}
	}
	portAliases := map[string]*model.Alias{}
	for _, e := range st.List(model.KindAlias) {
		if a := e.(*model.Alias); a.Type == "port" {
			portAliases[a.ID] = a
		}
	}
	covers := func(r *model.FilterRule, s *model.LBService, l4 string) bool {
		if r.Protocol != "any" && r.Protocol != l4 {
			return false
		}
		if r.SourceZone.ID != "" && r.SourceZone.ID != s.Zone.ID {
			return false
		}
		// A rule narrowed by address, tunnel or scope may leave clients
		// out; only an unrestricted one counts.
		if len(r.Source)+len(r.SourceNets)+len(r.Destination)+len(r.DestinationNets) > 0 || r.Tunnel.ID != "" || r.RateLimit != "" {
			return false
		}
		if r.Scope != "" && r.Scope != model.ScopeGlobal && r.Scope != s.Scope {
			return false
		}
		ports := append([]string(nil), r.Ports...)
		for _, ref := range r.PortAliases {
			if a := portAliases[ref.ID]; a != nil {
				ports = append(ports, a.Entries...)
			}
		}
		if len(ports) == 0 {
			return true
		}
		for _, p := range ports {
			lo, hi, isRange := strings.Cut(p, "-")
			a, _ := strconv.Atoi(lo)
			b := a
			if isRange {
				b, _ = strconv.Atoi(hi)
			}
			if s.Port >= a && s.Port <= b {
				return true
			}
		}
		return false
	}
	var out []Hint
	for _, e := range st.List(model.KindLBService) {
		s := e.(*model.LBService)
		if !s.Enabled || s.Mode != "proxy" {
			continue
		}
		l4 := "tcp"
		if s.Protocol == "udp" {
			l4 = "udp"
		}
		h := Hint{Service: s.ID, Name: s.Name}
		for _, r := range rules {
			if covers(r, s, l4) {
				h.Covered = true
				break
			}
		}
		if !h.Covered {
			name := "lb-" + s.Name
			if len(name) > 63 {
				name = name[:63]
			}
			rule := &model.FilterRule{Meta: model.Meta{Name: name, Scope: s.Scope,
				Description: "Lets clients reach the load-balancer service " + s.Name},
				Sequence: 500, Enabled: true, Action: "accept", Direction: "in", SourceZone: s.Zone,
				Protocol: l4, Ports: []string{strconv.Itoa(s.Port)}}
			if s.Address != "" {
				rule.DestinationNets = []string{s.Address}
			}
			h.Rule = rule
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
