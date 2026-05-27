package discovery

import "testing"

func TestClassifyDevice(t *testing.T) {
	cases := []struct {
		name string
		dev  Device
		want string
	}{
		{"lldp router wins", Device{LLDPCapabilities: []string{"router"}, Vendor: "Apple, Inc."}, "router"},
		{"lldp ap", Device{LLDPCapabilities: []string{"WLAN Access Point"}}, "ap"},
		{"snmp firewall", Device{SysDescr: "FortiGate-60F firewall"}, "firewall"},
		{"snmp switch", Device{SysDescr: "Cisco Catalyst 2960"}, "switch"},
		{"raspberry pi sbc", Device{Vendor: "Raspberry Pi Trading Ltd"}, "sbc"},
		{"hypervisor", Device{Vendor: "VMware, Inc."}, "hypervisor"},
		{"printer vendor", Device{Vendor: "Brother Industries"}, "printer"},
		{"printer port", Device{OpenPorts: []uint16{9100}}, "printer"},
		{"ipp port", Device{OpenPorts: []uint16{631}}, "printer"},
		{"rdp workstation", Device{OpenPorts: []uint16{3389}}, "workstation"},
		{"nfs nas", Device{OpenPorts: []uint16{111, 2049}}, "nas"},
		{"ssh server shape", Device{OpenPorts: []uint16{22, 443, 5432}}, "server"},
		{"web-only iot", Device{OpenPorts: []uint16{80}}, "iot"},
		{"randomized mobile", Device{MACType: MACTypeRandomized}, "mobile"},
		{"mobile vendor with server ports stays server", Device{Vendor: "Apple, Inc.", OpenPorts: []uint16{22, 443}}, "server"},
		{"unknown", Device{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyDevice(c.dev); got != c.want {
				t.Errorf("classifyDevice(%+v) = %q, want %q", c.dev, got, c.want)
			}
		})
	}
}
