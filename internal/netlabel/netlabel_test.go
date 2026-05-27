package netlabel

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		ip     string
		scope  Scope
		class  string
		detail string
	}{
		{"8.8.8.8", ScopePublic, "A", "global"},
		{"1.1.1.1", ScopePublic, "A", "global"},
		{"172.217.0.0", ScopePublic, "B", "global"},
		{"203.0.113.5", ScopePublic, "C", "global"},
		{"10.0.0.1", ScopePrivate, "A", "RFC1918"},
		{"172.16.5.4", ScopePrivate, "B", "RFC1918"},
		{"172.31.255.1", ScopePrivate, "B", "RFC1918"},
		{"192.168.1.20", ScopePrivate, "C", "RFC1918"},
		{"100.64.0.1", ScopePrivate, "A", "CGNAT"},
		{"100.127.255.1", ScopePrivate, "A", "CGNAT"},
		{"127.0.0.1", ScopeInternal, "A", "loopback"},
		{"169.254.1.1", ScopeInternal, "B", "link-local"},
		{"0.0.0.0", ScopeInternal, "A", "unspecified"},
		{"255.255.255.255", ScopeInternal, "E", "broadcast"},
		{"224.0.0.251", ScopeMulticast, "D", "multicast"},
		{"239.255.255.250", ScopeMulticast, "D", "multicast"},
		{"240.0.0.1", ScopeUnknown, "E", "reserved"},
		// IPv6
		{"2606:4700:4700::1111", ScopePublic, "", "global"},
		{"fd00::1", ScopePrivate, "", "ULA"},
		{"::1", ScopeInternal, "", "loopback"},
		{"fe80::1", ScopeInternal, "", "link-local"},
		{"ff02::1", ScopeMulticast, "", "multicast"},
		{"::", ScopeInternal, "", "unspecified"},
		// junk
		{"not-an-ip", ScopeUnknown, "", ""},
		{"", ScopeUnknown, "", ""},
	}
	for _, c := range cases {
		got := Classify(c.ip)
		if got.Scope != c.scope || got.Class != c.class || got.Detail != c.detail {
			t.Errorf("Classify(%q) = {%s %q %q}, want {%s %q %q}",
				c.ip, got.Scope, got.Class, got.Detail, c.scope, c.class, c.detail)
		}
	}
}

func TestTag(t *testing.T) {
	cases := []struct {
		ip  string
		tag string
	}{
		{"192.168.1.1", "prv·C"},
		{"8.8.8.8", "pub·A"},
		{"127.0.0.1", "int·A"},
		{"fd00::1", "prv"},
		{"224.0.0.251", "mcast·D"},
	}
	for _, c := range cases {
		if got := Classify(c.ip).Tag(); got != c.tag {
			t.Errorf("Classify(%q).Tag() = %q, want %q", c.ip, got, c.tag)
		}
	}
}
