package discovery

import "strings"

// Device-type classification. Best-effort and order-sensitive: stronger,
// protocol-grounded signals (LLDP capabilities, SNMP sysDescr) win over weaker
// heuristics (vendor OUI, open-port shape). Always returns quickly and never
// blocks discovery. An empty result means "couldn't tell" - the caller leaves
// any existing type untouched.
//
// Coarse classes: "router", "switch", "ap", "firewall", "printer", "nas",
// "server", "workstation", "mobile", "sbc", "iot", "hypervisor".

// infraVendors are OUI vendor substrings that imply network infrastructure.
var infraVendors = []string{
	"cisco", "juniper", "arista", "ubiquiti", "mikrotik", "tp-link",
	"netgear", "aruba", "ruckus", "fortinet", "palo alto", "meraki",
	"d-link", "zyxel", "huawei",
}

var printerVendors = []string{"hewlett", "lexmark", "brother", "canon", "epson", "xerox", "kyocera"}
var nasVendors = []string{"synology", "qnap", "western digital", "netgear"}
var mobileVendors = []string{"apple", "samsung", "xiaomi", "huawei", "oneplus", "google"}
var hypervisorVendors = []string{"vmware", "virtualbox", "hyper-v", "parallels", "qemu", "kvm", "xen"}

// classifyDevice derives a coarse device type from the accumulated signals on
// d. Returns "" when no signal is strong enough.
func classifyDevice(d Device) string {
	// 1. LLDP system capabilities - authoritative for managed gear.
	if t := classifyByLLDP(d.LLDPCapabilities); t != "" {
		return t
	}
	// 2. SNMP sysDescr keywords.
	if t := classifyBySysDescr(d.SysDescr); t != "" {
		return t
	}
	// 3. Vendor OUI families.
	if t := classifyByVendor(d.Vendor); t != "" {
		// Refine generic vendor guesses with port evidence where useful.
		if t == "mobile" && hasServerPortShape(d.OpenPorts) {
			return "server"
		}
		return t
	}
	// 4. Open-port shape.
	if t := classifyByPorts(d.OpenPorts); t != "" {
		return t
	}
	// 5. A randomized MAC with no other signal is almost always a phone/laptop
	//    using privacy addressing.
	if d.MACType == MACTypeRandomized {
		return "mobile"
	}
	return ""
}

func classifyByLLDP(caps []string) string {
	has := func(want string) bool {
		for _, c := range caps {
			if strings.Contains(strings.ToLower(c), want) {
				return true
			}
		}
		return false
	}
	switch {
	case has("router"):
		return "router"
	case has("wlan") || has("ap") || has("access"):
		return "ap"
	case has("bridge") || has("switch"):
		return "switch"
	case has("telephone") || has("phone"):
		return "mobile"
	}
	return ""
}

func classifyBySysDescr(descr string) string {
	d := strings.ToLower(descr)
	if d == "" {
		return ""
	}
	switch {
	case containsAny(d, "router", "ios", "routeros", "edgeos"):
		return "router"
	case containsAny(d, "switch", "catalyst"):
		return "switch"
	case containsAny(d, "access point", "wireless", "wlan", "wifi"):
		return "ap"
	case containsAny(d, "firewall", "fortigate", "pan-os", "asa"):
		return "firewall"
	case containsAny(d, "printer", "jetdirect", "laserjet"):
		return "printer"
	}
	return ""
}

func classifyByVendor(vendor string) string {
	v := strings.ToLower(vendor)
	if v == "" {
		return ""
	}
	switch {
	case containsAny(v, "raspberry pi"):
		return "sbc"
	case matchesAny(v, hypervisorVendors):
		return "hypervisor"
	case matchesAny(v, printerVendors):
		return "printer"
	case matchesAny(v, nasVendors):
		return "nas"
	case matchesAny(v, infraVendors):
		return "switch" // generic network-gear bucket; LLDP/SNMP refine it
	case matchesAny(v, mobileVendors):
		return "mobile"
	}
	return ""
}

// classifyByPorts infers a role from the open-port fingerprint.
func classifyByPorts(ports []uint16) string {
	set := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		set[p] = true
	}
	switch {
	case set[9100] || set[631]: // raw-print / IPP
		return "printer"
	case set[3389]: // RDP
		return "workstation"
	case set[445] && set[139]: // SMB
		return "workstation"
	case set[2049] || set[111]: // NFS
		return "nas"
	case hasServerPortShape(ports):
		return "server"
	case (set[80] || set[443]) && len(ports) <= 2:
		return "iot"
	}
	return ""
}

// hasServerPortShape is true when SSH is open alongside at least one other
// service - the typical signature of a Linux/Unix server.
func hasServerPortShape(ports []uint16) bool {
	set := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		set[p] = true
	}
	return set[22] && len(ports) >= 2
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
