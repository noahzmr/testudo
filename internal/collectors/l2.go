package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// L2Collector watches two cheap L2 signals that L3 monitoring misses
// entirely:
//
//   - per-interface multicast rate (the kernel's Multicast counter
//     covers both broadcast and multicast on most NICs - useful for
//     spotting ARP storms, mDNS chatter, or runaway services).
//   - ARP-table churn: when an IP starts resolving to a different MAC
//     between samples it's either an IP conflict or a rogue device.
//
// Both checks run on the same tick so we can hold one prev-snapshot per
// signal type. Rates are alerted only when they grow by more than
// MulticastThreshold packets per Interval; ARP changes are always
// alerted.
type L2Collector struct {
	Netops             *netops.Writer
	Interval           time.Duration
	MulticastThreshold uint64
}

func (c *L2Collector) Name() string { return "l2" }

type l2IfaceSnap struct {
	multicast uint64
}

func (c *L2Collector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Netops == nil || c.Interval <= 0 {
		return nil
	}
	if c.MulticastThreshold == 0 {
		c.MulticastThreshold = 1000
	}
	ifPrev := map[string]l2IfaceSnap{}
	arpPrev := readARPTable()

	if ifs, err := c.Netops.ListIfaces(); err == nil {
		for _, ifi := range ifs {
			if ifi.Name == "lo" {
				continue
			}
			ifPrev[ifi.Name] = l2IfaceSnap{multicast: ifi.Multicast}
		}
	}

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.checkInterfaces(bus, ifPrev)
			arpPrev = c.checkARP(bus, arpPrev)
		}
	}
}

func (c *L2Collector) checkInterfaces(bus *events.Bus, prev map[string]l2IfaceSnap) {
	ifs, err := c.Netops.ListIfaces()
	if err != nil {
		return
	}
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		p, seen := prev[ifi.Name]
		cur := l2IfaceSnap{multicast: ifi.Multicast}
		prev[ifi.Name] = cur
		if !seen {
			continue
		}
		if d := delta(cur.multicast, p.multicast); d > c.MulticastThreshold {
			sev := events.SevInfo
			if d > c.MulticastThreshold*10 {
				sev = events.SevWarn
			}
			bus.Publish(events.Event{
				Kind: events.KindAnomaly, Source: c.Name(),
				Payload: events.AnomalyPayload{
					Severity: string(sev),
					Message: fmt.Sprintf("%s multicast/broadcast burst: +%d packets in %s",
						ifi.Name, d, c.Interval),
				},
			})
		}
	}
}

// checkARP compares the previous and current ARP tables and fires
// anomalies on IP→MAC reassignments. New IPs are not alerted - that's
// just normal discovery. Disappearances (IP no longer in table) are
// not alerted either; netlink and the dhcp client churn the table
// often enough that quiet drops aren't operationally interesting.
func (c *L2Collector) checkARP(bus *events.Bus, prev map[string]string) map[string]string {
	cur := readARPTable()
	for ip, mac := range cur {
		if mac == "00:00:00:00:00:00" || mac == "" {
			continue
		}
		oldMAC, seen := prev[ip]
		if !seen {
			continue
		}
		if oldMAC == mac {
			continue
		}
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("ARP changed for %s: %s -> %s (IP conflict or rogue device?)",
					ip, oldMAC, mac),
			},
		})
	}
	return cur
}

// readARPTable parses /proc/net/arp into an IP->MAC map. Format:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0
//
// Flags=0x0 entries are "incomplete" lookups (kernel asked, no reply
// yet) - their MAC is 00:00:00:00:00:00 and they're filtered out by the
// caller.
func readARPTable() map[string]string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		out[ip] = mac
	}
	return out
}
