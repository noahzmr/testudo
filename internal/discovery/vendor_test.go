package discovery

import "testing"

func TestNormalizeMAC(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"d8:3a:dd:12:34:56", "D8:3A:DD:12:34:56"},
		{"D8-3A-DD-12-34-56", "D8:3A:DD:12:34:56"},
		{"d83a.dd12.3456", "D8:3A:DD:12:34:56"},
		{"D8:3A:DD:12:34:56:78", "D8:3A:DD:12:34:56"}, // extra octet trimmed
		{"  d8:3a:dd:12:34:56  ", "D8:3A:DD:12:34:56"},
		{"00:00:00:00:00:00", "00:00:00:00:00:00"},
		{"short", ""},
		{"zz:3a:dd:12:34:56", ""}, // non-hex
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeMAC(c.in); got != c.want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClassifyMAC(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"D8:3A:DD:12:34:56", MACTypeGlobal},     // first octet 0xD8: bits clear
		{"DA:3A:DD:12:34:56", MACTypeRandomized}, // 0xDA: locally-administered bit
		{"01:00:5E:00:00:01", MACTypeMulticast},  // 0x01: multicast bit
		{"02:11:22:33:44:55", MACTypeRandomized}, // 0x02: local bit
		{"", ""},
	}
	for _, c := range cases {
		if got := classifyMAC(c.in); got != c.want {
			t.Errorf("classifyMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVendorFor(t *testing.T) {
	// Known global OUI resolves via the IEEE database.
	if v := vendorFor("D8:3A:DD:12:34:56"); v == "" {
		t.Error("vendorFor(D8:3A:DD:..) returned empty; expected a Raspberry Pi vendor")
	}
	// Override map wins for hypervisor MACs.
	if v := vendorFor("00:50:56:aa:bb:cc"); v != "VMware" {
		t.Errorf("vendorFor(VMware OUI) = %q, want VMware", v)
	}
	// Randomized/local MAC carries no meaningful OUI.
	if v := vendorFor("DA:3A:DD:12:34:56"); v != "" {
		t.Errorf("vendorFor(randomized) = %q, want empty", v)
	}
	// Garbage in, empty out.
	if v := vendorFor("nonsense"); v != "" {
		t.Errorf("vendorFor(garbage) = %q, want empty", v)
	}
}
