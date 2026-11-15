package netops

import "fmt"

// OpSyncRouting makes the kernel's VRF devices and policy rules match a
// RoutingSpec (Op.Routing).
const OpSyncRouting OpKind = "routing_sync"

// RoutingVRF is one VRF device and its member interfaces.
type RoutingVRF struct {
	Name    string   `json:"name"`
	Table   uint32   `json:"table"`
	Members []string `json:"members,omitempty"`
}

// RoutingRule sends traffic carrying Mark to Table.
type RoutingRule struct {
	Priority int    `json:"priority"`
	Mark     uint32 `json:"mark"`
	Table    uint32 `json:"table"`
}

// RoutingSpec is the desired state of what the routing stage owns in the
// kernel outside the routing daemon. Rules in the priority range that are
// not listed are removed; so are VRF devices this program created.
type RoutingSpec struct {
	VRFs             []RoutingVRF  `json:"vrfs,omitempty"`
	Rules            []RoutingRule `json:"rules,omitempty"`
	RulePriorityLow  int           `json:"rule_priority_low"`
	RulePriorityHigh int           `json:"rule_priority_high"`
}

// SyncRouting applies spec. It is a mutation.
func (w *Writer) SyncRouting(spec RoutingSpec) error {
	if !w.AllowWrites {
		return fmt.Errorf("routing sync: writes are disabled")
	}
	if spec.RulePriorityLow <= 0 || spec.RulePriorityHigh < spec.RulePriorityLow {
		return fmt.Errorf("routing sync: bad rule priority range")
	}
	return w.mutate(Op{Kind: OpSyncRouting, Routing: &spec})
}
