package svcstage

import (
	"fmt"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/svcrender"
)

func TestDesiredNames(t *testing.T) {
	now := time.Now()
	res := svcrender.Result{
		Scopes: []svcrender.Scope{
			{SubnetID: 1, Domain: "home.arpa", Register: true},
			{SubnetID: 2, Domain: "guest.arpa", Register: false},
			{SubnetID: 1, V6: true, Domain: "home.arpa", Register: true},
		},
		StaticNames: []string{"nas.home.arpa"},
	}
	later := now.Add(time.Hour)
	leases := []Lease{
		{Address: "192.168.1.100", Hostname: "laptop.home.arpa", SubnetID: 1, Expires: later},
		{Address: "2001:db8:1::1000", Hostname: "laptop.home.arpa", SubnetID: 1, V6: true, Expires: later},
		{Address: "192.168.1.101", Hostname: "nas.home.arpa", SubnetID: 1, Expires: later},    // the model's name
		{Address: "192.168.1.102", Hostname: "evil.example.com", SubnetID: 1, Expires: later}, // outside the domain
		{Address: "192.168.1.103", Hostname: "old.home.arpa", SubnetID: 1, Expires: now.Add(-time.Minute)},
		{Address: "192.168.1.104", Hostname: "declined.home.arpa", SubnetID: 1, Expires: later, State: 1},
		{Address: "192.168.9.100", Hostname: "visitor.guest.arpa", SubnetID: 2, Expires: later}, // scope does not register
		{Address: "192.168.1.105", SubnetID: 1, Expires: later},                                 // no name
	}
	got := fmt.Sprint(DesiredNames(res, leases, now))
	if got != "map[laptop.home.arpa:[192.168.1.100 2001:db8:1::1000]]" {
		t.Errorf("names: %s", got)
	}
}
