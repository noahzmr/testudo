package replay

import "testing"

func TestLegacyWiFiSample(t *testing.T) {
	cases := []struct {
		label string
		us    float64
		want  float64
		ok    bool
	}{
		{"wifi:signal:wlan0", 60_000, -60, true}, // stored as -(-60 dBm) ms
		{"wifi:noise:wlan0", 95_000, -95, true},
		{"wifi:txpower:wlan0", -20_000, 20, true}, // stored as -(20 dBm) ms
		{"wifi:freq:wlan0", 5_180_000, 5180, true},
		{"wifi:tx-rate:wlan0", 864_800, 864.8, true},
		{"1.1.1.1", 12_000, 0, false},
	}
	for _, c := range cases {
		name, v, ok := legacyWiFiSample(c.label, c.us)
		if ok != c.ok || (ok && (v != c.want || name != c.label)) {
			t.Errorf("legacyWiFiSample(%q, %v) = %q, %v, %v; want %v, %v", c.label, c.us, name, v, ok, c.want, c.ok)
		}
	}
}
