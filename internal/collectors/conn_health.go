package collectors

import (
	"os"
	"strconv"
	"strings"
)

// connResetCounters holds the cumulative kernel TCP failure counters the
// reset/refused-rate signal is derived from. AttemptFails counts connection
// attempts that gave up (refused or timed-out connects); EstabResets counts
// established connections torn down by RST. Both come from /proc/net/snmp.
type connResetCounters struct {
	attemptFails uint64
	estabResets  uint64
	ok           bool
}

// readTCPResetCounters reads AttemptFails / EstabResets from the Tcp: row of
// /proc/net/snmp. ok=false (zeroed) when the file or fields are unreadable, so
// the caller treats a parse failure as "no data" rather than a fake spike.
func readTCPResetCounters() connResetCounters {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return connResetCounters{}
	}
	lines := strings.Split(string(data), "\n")
	var header []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line)
		if header == nil {
			header = fields // first Tcp: line is the field-name header
			continue
		}
		// Second Tcp: line is the values; map by header position.
		out := connResetCounters{ok: true}
		for i := 1; i < len(header) && i < len(fields); i++ {
			switch header[i] {
			case "AttemptFails":
				out.attemptFails, _ = strconv.ParseUint(fields[i], 10, 64)
			case "EstabResets":
				out.estabResets, _ = strconv.ParseUint(fields[i], 10, 64)
			}
		}
		return out
	}
	return connResetCounters{}
}

// readEphemeralPortRange reads /proc/sys/net/ipv4/ip_local_port_range (a
// "low<TAB>high" pair). Returns the kernel default 32768..60999 when the file
// can't be read, so utilisation maths always has a sane denominator.
func readEphemeralPortRange() (low, high int) {
	low, high = 32768, 60999
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return low, high
	}
	f := strings.Fields(string(data))
	if len(f) != 2 {
		return low, high
	}
	l, err1 := strconv.Atoi(f[0])
	h, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || h <= l {
		return 32768, 60999
	}
	return l, h
}
