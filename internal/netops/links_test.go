package netops

import (
	"strings"
	"testing"
)

func TestLinksSpecIsChecked(t *testing.T) {
	ok := LinksSpec{Links: []LinkSpec{
		{Name: "bond0", Kind: "bond", Members: []string{"eth0", "eth1"}},
		{Name: "bond0.10", Kind: "vlan", Parent: "bond0", VID: 10},
		{Name: "br0", Kind: "bridge", Members: []string{"eth2"}},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for want, spec := range map[string]LinksSpec{
		"bad device name": {Links: []LinkSpec{{Name: "-x", Kind: "bond"}}},
		"twice":           {Links: []LinkSpec{{Name: "br0", Kind: "bridge"}, {Name: "br0", Kind: "bridge"}}},
		"1 to 4094":       {Links: []LinkSpec{{Name: "v", Kind: "vlan", Parent: "eth0", VID: 4095}}},
		"unknown kind":    {Links: []LinkSpec{{Name: "t0", Kind: "tun"}}},
		"member of both":  {Links: []LinkSpec{{Name: "bond0", Kind: "bond", Members: []string{"eth0"}}, {Name: "br0", Kind: "bridge", Members: []string{"eth0"}}}},
		"bad member":      {Links: []LinkSpec{{Name: "bond0", Kind: "bond", Members: []string{"bond0"}}}},
		"protocol":        {Links: []LinkSpec{{Name: "v", Kind: "vlan", Parent: "eth0", VID: 5, Protocol: "isl"}}},
	} {
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}
