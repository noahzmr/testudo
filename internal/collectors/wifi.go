package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/wifi"

	"github.com/noahzmr/testudo/internal/events"
)

// WiFiSnapshot is the per-interface rich wireless state the collector
// publishes every tick. Zero-valued fields mean "unknown" — drivers
// vary widely in what they expose through `iw` / /proc/net/wireless, so
// renderers should treat empty strings and zero numerics as "no data"
// rather than as a measurement.
type WiFiSnapshot struct {
	Iface       string    // interface name (e.g. wlan0)
	HWAddr      string    // local MAC address
	PhyType     string    // managed / monitor / ap / ibss
	SSID        string    // associated network name
	BSSID       string    // associated AP MAC
	Country     string    // regulatory domain when iw reports it
	Frequency   int       // operating frequency in MHz
	Channel     int       // channel number derived from frequency
	ChannelWMHz int       // channel width in MHz (20/40/80/160)
	Band        string    // "2.4 GHz" / "5 GHz" / "6 GHz"
	Signal      float64   // current RX signal level, dBm
	SignalAvg   float64   // averaged RX signal level, dBm (if reported)
	Noise       float64   // noise floor, dBm (negative; 0 = unknown)
	TXBitrateM  float64   // current TX bitrate, Mbit/s
	RXBitrateM  float64   // current RX bitrate, Mbit/s
	TXPower     float64   // radio TX power, dBm
	LinkQuality float64   // 0..100 (derived from /proc/net/wireless "link"
	//                       column when present; iw doesn't expose this)
	LinkMax     int       // driver-reported link-quality maximum (e.g. 70)
	Retries     uint64    // cumulative TX retries since boot
	BeaconLoss  uint64    // missed beacons since boot
	RxBytes     uint64    // station-level RX bytes (from `iw station dump`)
	TxBytes     uint64    // station-level TX bytes
	RxPackets   uint64    // station-level RX packets
	TxPackets   uint64    // station-level TX packets
	TxFailed    uint64    // TX failures reported by the driver
	ConnectedAt time.Time // monotonic ConnectedTime mapped to wall-clock
	Associated  bool      // true when the radio has joined an AP
	Wireless    bool      // true for any /sys/class/net/<iface>/wireless NIC
	Updated     time.Time // time the snapshot was last refreshed

	// Source records which backend filled this snapshot. Useful in the UI
	// to explain why a row has only "signal" + "retries" (legacy
	// /proc/net/wireless) vs. the full nl80211 set (iw).
	Source string
}

// WiFiCollector reports per-interface wireless state on every tick. It
// fuses three data sources:
//
//   - /sys/class/net/<iface>/wireless : kernel-canonical "this iface is
//     a wireless NIC" signal. Used for enumeration so we still surface
//     unassociated radios (no /proc/net/wireless row, no `iw link`
//     output).
//   - `iw` userspace tool (preferred) : SSID, BSSID, channel,
//     frequency, bitrate, txpower, noise, station-level counters,
//     connected time. Available on all modern distros.
//   - /proc/net/wireless (fallback) : signal level + retry / beacon
//     counters. Kept for systems without iw installed.
//
// Every tick the collector:
//
//   - rebuilds the per-iface snapshot, cached behind a RWMutex so the
//     TUI and Web UI can read it without locking out the next sample,
//   - emits one KindLatency event per (iface, metric) so the metrics
//     aggregator, history series, and grade machinery keep working
//     unchanged. Signal/noise/TX power use a negated-millisecond
//     encoding (RTT = -value_dBm * ms) so the existing renderers can
//     flip the sign back; bitrate / frequency / channel-width are
//     encoded positive in ms (Mbit/s and MHz are >= 0).
//   - emits anomalies for low signal, lost association, growing
//     retries, and growing TX failures.
type WiFiCollector struct {
	Interval  time.Duration
	MinSignal float64

	mu   sync.RWMutex
	snap map[string]WiFiSnapshot

	prev map[string]wifiSnap

	// nlClient is the nl80211 netlink socket. Opened lazily on first
	// sample so the collector still loads on kernels without nl80211
	// (the same code path used to fall back to iw / /proc).
	nlOnce   sync.Once
	nlClient *wifi.Client
}

// wifiSnap is the lightweight prev-tick comparator used for anomaly
// detection. The richer WiFiSnapshot is what we expose.
type wifiSnap struct {
	signal     float64
	retries    uint64
	failed     uint64
	beaconLoss uint64
	associated bool
}

func (c *WiFiCollector) Name() string { return "wifi" }

// Snapshot returns a defensively-copied slice of every wireless iface
// the collector has observed, sorted by interface name. Safe to call
// from any goroutine.
func (c *WiFiCollector) Snapshot() []WiFiSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]WiFiSnapshot, 0, len(c.snap))
	for _, s := range c.snap {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}

func (c *WiFiCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Interval <= 0 {
		return nil
	}
	if c.MinSignal == 0 {
		c.MinSignal = -75
	}
	c.snap = map[string]WiFiSnapshot{}
	c.prev = c.sampleAndStore()

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cur := c.sampleAndStore()
			for iface, s := range cur {
				rich := c.lookup(iface)
				c.publishMetrics(bus, iface, rich)

				p, seen := c.prev[iface]
				if !seen {
					continue
				}
				c.detectAnomalies(bus, iface, p, s, rich)
			}
			c.prev = cur
		}
	}
}

// lookup returns the cached rich snapshot for iface, or a zero value if
// nothing has been recorded yet (shouldn't happen in practice — sample
// runs first).
func (c *WiFiCollector) lookup(iface string) WiFiSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap[iface]
}

// publishMetrics emits one KindLatency event per scalar wifi metric so
// the existing metrics aggregator / history / grade machinery keeps
// working without a dedicated WiFi event payload. Targets are namespaced
// under "wifi:<metric>:<iface>" so renderers can route them.
func (c *WiFiCollector) publishMetrics(bus *events.Bus, iface string, s WiFiSnapshot) {
	emit := func(metric string, valueMs float64) {
		// negative signal levels encode as positive duration via -ms ;
		// positive metrics (bitrate, freq) use ms directly. Renderers
		// flip the sign back based on the metric prefix.
		bus.Publish(events.Event{
			Kind: events.KindLatency, Source: c.Name(),
			Payload: events.LatencyPayload{
				Target: "wifi:" + metric + ":" + iface,
				RTT:    time.Duration(valueMs * float64(time.Millisecond)),
			},
		})
	}
	emit("signal", -s.Signal)
	if s.Noise != 0 {
		emit("noise", -s.Noise)
	}
	if s.TXBitrateM > 0 {
		emit("tx-rate", s.TXBitrateM)
	}
	if s.RXBitrateM > 0 {
		emit("rx-rate", s.RXBitrateM)
	}
	if s.Frequency > 0 {
		emit("freq", float64(s.Frequency))
	}
	if s.TXPower > 0 {
		emit("txpower", -s.TXPower) // dBm — encode negated like signal
	}
	if s.LinkQuality > 0 {
		emit("quality", s.LinkQuality)
	}
}

func (c *WiFiCollector) detectAnomalies(bus *events.Bus, iface string, prev wifiSnap, cur wifiSnap, rich WiFiSnapshot) {
	if cur.associated && cur.signal != 0 && cur.signal < c.MinSignal {
		sev := events.SevWarn
		if cur.signal < c.MinSignal-15 {
			sev = events.SevError
		}
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(sev),
				Message: fmt.Sprintf("%s signal %.0fdBm (threshold %.0f) ssid=%q",
					iface, cur.signal, c.MinSignal, rich.SSID),
			},
		})
	}
	if prev.associated && !cur.associated {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  fmt.Sprintf("%s wireless lost association", iface),
			},
		})
	}
	if dRetries := delta(cur.retries, prev.retries); dRetries > 0 {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevInfo),
				Message:  fmt.Sprintf("%s retries growing: +%d", iface, dRetries),
			},
		})
	}
	if dFail := delta(cur.failed, prev.failed); dFail > 0 {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  fmt.Sprintf("%s TX failures growing: +%d", iface, dFail),
			},
		})
	}
	if dBeacon := delta(cur.beaconLoss, prev.beaconLoss); dBeacon > 0 {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevInfo),
				Message:  fmt.Sprintf("%s beacons missed: +%d", iface, dBeacon),
			},
		})
	}
}

// sampleAndStore refreshes the rich snapshot map and returns the
// lightweight prev-tick comparator the anomaly detector uses.
//
// Backends, in order of preference:
//
//  1. nl80211 via mdlayher/wifi - the modern kernel API; the same
//     interface `iw` itself uses. Works on every recent driver
//     (iwlwifi, mt76, ath11k, brcmfmac, etc.) and doesn't need any
//     userspace binary installed. Requires CAP_NET_ADMIN on some
//     distros; otherwise we just see empty results and fall through.
//  2. `iw` userspace command - shells out, kept as a fallback for
//     systems where nl80211 access is denied but the iw binary works
//     (eg. distros that wrap iw in a setuid helper).
//  3. /proc/net/wireless - the legacy wireless-extensions API. Most
//     modern drivers leave this completely empty, but some (mt7601u,
//     legacy rt2x00) still write to it.
//
// Each backend populates the same WiFiSnapshot; later backends only
// fill fields the earlier ones left empty, so users on systems where
// only the legacy interface works still get partial data.
func (c *WiFiCollector) sampleAndStore() map[string]wifiSnap {
	wireless := listWirelessIfaces()
	proc, _ := readWireless()
	out := map[string]wifiSnap{}
	rich := map[string]WiFiSnapshot{}
	iwAvailable := iwBinaryAvailable()

	// nl80211 client is opened lazily once; if the kernel doesn't
	// expose nl80211 or we lack CAP_NET_ADMIN, nlByIface returns nil.
	nlByIface := c.sampleNL80211(wireless)

	now := time.Now()
	for _, iface := range wireless {
		s := WiFiSnapshot{Iface: iface, Wireless: true, Updated: now}
		if mac, _ := os.ReadFile("/sys/class/net/" + iface + "/address"); len(mac) > 0 {
			s.HWAddr = strings.TrimSpace(string(mac))
		}

		// Layer 1: nl80211 — the primary source on modern kernels.
		// Fills SSID, BSSID, freq, channel width, signal, bitrate,
		// station counters in one round-trip.
		if nl, ok := nlByIface[iface]; ok {
			s.SSID = nl.SSID
			s.BSSID = nl.BSSID
			s.Frequency = nl.Frequency
			s.ChannelWMHz = nl.ChannelWMHz
			s.PhyType = nl.PhyType
			if nl.Signal != 0 {
				s.Signal = nl.Signal
			}
			if nl.SignalAvg != 0 {
				s.SignalAvg = nl.SignalAvg
			}
			if nl.TXBitrateM > 0 {
				s.TXBitrateM = nl.TXBitrateM
			}
			if nl.RXBitrateM > 0 {
				s.RXBitrateM = nl.RXBitrateM
			}
			s.Retries = nl.Retries
			s.TxFailed = nl.TxFailed
			s.BeaconLoss = nl.BeaconLoss
			s.RxBytes = nl.RxBytes
			s.TxBytes = nl.TxBytes
			s.RxPackets = nl.RxPackets
			s.TxPackets = nl.TxPackets
			if nl.ConnectedSec > 0 {
				s.ConnectedAt = time.Now().Add(-time.Duration(nl.ConnectedSec) * time.Second)
			}
			if s.SSID != "" || s.BSSID != "" || s.Signal != 0 {
				s.Associated = true
				s.Source = "nl80211"
			} else if nl.PhyType != "" {
				s.Source = "nl80211"
			}
		}

		// Layer 2: /proc/net/wireless. Only fills gaps - if nl80211
		// already gave us a signal we keep it.
		if p, ok := proc[iface]; ok {
			if s.Signal == 0 {
				s.Signal = p.signal
			}
			if s.Retries == 0 {
				s.Retries = p.retries
			}
			if s.BeaconLoss == 0 {
				s.BeaconLoss = p.beaconLoss
			}
			s.LinkQuality, s.LinkMax = p.link, p.linkMax
			if !s.Associated && (p.signal != 0 || p.retries != 0 || p.link != 0) {
				s.Associated = true
			}
			if s.Source == "" {
				s.Source = "proc"
			} else if s.Source == "nl80211" && (p.link != 0 || p.signal != 0) {
				s.Source = "nl80211+proc"
			}
		}

		// Layer 3: iw — last-resort fallback. Only runs when nl80211
		// gave us nothing meaningful, since iw itself just wraps
		// nl80211 (anything iw can see, mdlayher/wifi can see too).
		if iwAvailable && (s.SSID == "" && s.BSSID == "" && s.Frequency == 0) {
			parseIWInfo(iface, &s)
			parseIWLink(iface, &s)
			parseIWStation(iface, &s)
			if s.SSID != "" || s.BSSID != "" || s.Frequency > 0 {
				s.Associated = true
				if s.Source == "" {
					s.Source = "iw"
				} else {
					s.Source += "+iw"
				}
			}
		}

		if s.Source == "" {
			s.Source = "none"
		}

		if s.Frequency > 0 {
			s.Channel = freqToChannel(s.Frequency)
			s.Band = freqToBand(s.Frequency)
		}

		rich[iface] = s
		out[iface] = wifiSnap{
			signal: s.Signal, retries: s.Retries,
			failed: s.TxFailed, beaconLoss: s.BeaconLoss,
			associated: s.Associated,
		}
	}
	c.mu.Lock()
	c.snap = rich
	c.mu.Unlock()
	return out
}

// nl80211Snapshot holds the fields the nl80211 backend can populate.
// Kept separate from WiFiSnapshot so the merge logic stays explicit.
type nl80211Snapshot struct {
	SSID, BSSID  string
	PhyType      string
	Frequency    int
	ChannelWMHz  int
	Signal       float64
	SignalAvg    float64
	TXBitrateM   float64
	RXBitrateM   float64
	Retries      uint64
	TxFailed     uint64
	BeaconLoss   uint64
	RxBytes      uint64
	TxBytes      uint64
	RxPackets    uint64
	TxPackets    uint64
	ConnectedSec int64
}

// sampleNL80211 walks every wireless iface via the cached nl80211
// client and returns a per-iface snapshot. Returns nil (the empty
// map) when the kernel/permissions don't allow nl80211 access — the
// caller falls through to /proc and iw.
func (c *WiFiCollector) sampleNL80211(wireless []string) map[string]nl80211Snapshot {
	c.nlOnce.Do(func() {
		if cli, err := wifi.New(); err == nil {
			c.nlClient = cli
		}
	})
	if c.nlClient == nil {
		return nil
	}
	ifs, err := c.nlClient.Interfaces()
	if err != nil {
		return nil
	}
	want := map[string]bool{}
	for _, n := range wireless {
		want[n] = true
	}
	out := map[string]nl80211Snapshot{}
	for _, ifi := range ifs {
		if !want[ifi.Name] {
			continue
		}
		snap := nl80211Snapshot{
			Frequency:   ifi.Frequency,
			ChannelWMHz: channelWidthMHz(ifi.ChannelWidth),
			PhyType:     interfaceTypeString(ifi.Type),
		}
		// BSS returns SSID/BSSID/signal of the AP we're associated
		// with. ErrNotSupported / no-BSS errors are fine - they just
		// mean the radio isn't joined to a network.
		if bss, err := c.nlClient.BSS(ifi); err == nil && bss != nil {
			snap.SSID = bss.SSID
			if bss.BSSID != nil {
				snap.BSSID = bss.BSSID.String()
			}
			if bss.Frequency > 0 {
				snap.Frequency = bss.Frequency
			}
			// Signal is reported in mBm (milli-dBm); /100 gives dBm.
			if bss.Signal != 0 {
				snap.Signal = float64(bss.Signal) / 100.0
			}
		}
		// StationInfo returns per-AP counters. In client (managed)
		// mode there's exactly one station - the AP - so we read the
		// first record. Some drivers return an empty slice when
		// unassociated; that's fine.
		if stas, err := c.nlClient.StationInfo(ifi); err == nil && len(stas) > 0 {
			st := stas[0]
			if snap.Signal == 0 && st.Signal != 0 {
				snap.Signal = float64(st.Signal)
			}
			if st.SignalAverage != 0 {
				snap.SignalAvg = float64(st.SignalAverage)
			}
			// Bitrates are reported in bits/sec; convert to Mbit/s.
			if st.TransmitBitrate > 0 {
				snap.TXBitrateM = float64(st.TransmitBitrate) / 1e6
			}
			if st.ReceiveBitrate > 0 {
				snap.RXBitrateM = float64(st.ReceiveBitrate) / 1e6
			}
			snap.Retries = uint64(st.TransmitRetries)
			snap.TxFailed = uint64(st.TransmitFailed)
			snap.BeaconLoss = uint64(st.BeaconLoss)
			snap.RxBytes = uint64(st.ReceivedBytes)
			snap.TxBytes = uint64(st.TransmittedBytes)
			snap.RxPackets = uint64(st.ReceivedPackets)
			snap.TxPackets = uint64(st.TransmittedPackets)
			snap.ConnectedSec = int64(st.Connected.Seconds())
		}
		out[ifi.Name] = snap
	}
	return out
}

// channelWidthMHz maps the library's ChannelWidth enum back to a
// human-readable MHz value. Unknown widths return 0 so the renderer
// can omit the column rather than print a misleading 20 MHz default.
func channelWidthMHz(cw wifi.ChannelWidth) int {
	switch cw {
	case wifi.ChannelWidth20NoHT, wifi.ChannelWidth20:
		return 20
	case wifi.ChannelWidth40:
		return 40
	case wifi.ChannelWidth80:
		return 80
	case wifi.ChannelWidth80P80:
		return 160 // two 80 MHz halves
	case wifi.ChannelWidth160:
		return 160
	case wifi.ChannelWidth5:
		return 5
	case wifi.ChannelWidth10:
		return 10
	}
	return 0
}

// interfaceTypeString turns the nl80211 mode enum into the same
// strings `iw dev <iface> info` would print under "type". Keeps the
// front-end agnostic to which backend filled the value.
func interfaceTypeString(t wifi.InterfaceType) string {
	switch t {
	case wifi.InterfaceTypeAdHoc:
		return "ibss"
	case wifi.InterfaceTypeStation:
		return "managed"
	case wifi.InterfaceTypeAP:
		return "ap"
	case wifi.InterfaceTypeAPVLAN:
		return "ap_vlan"
	case wifi.InterfaceTypeWDS:
		return "wds"
	case wifi.InterfaceTypeMonitor:
		return "monitor"
	case wifi.InterfaceTypeMeshPoint:
		return "mesh"
	case wifi.InterfaceTypeP2PClient:
		return "p2p_client"
	case wifi.InterfaceTypeP2PGroupOwner:
		return "p2p_go"
	case wifi.InterfaceTypeP2PDevice:
		return "p2p_device"
	case wifi.InterfaceTypeOCB:
		return "ocb"
	case wifi.InterfaceTypeNAN:
		return "nan"
	}
	return ""
}

// listWirelessIfaces returns interface names that have a "wireless"
// subdirectory under /sys/class/net. The kernel adds this directory for
// any wifi NIC regardless of association state.
func listWirelessIfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if _, err := os.Stat("/sys/class/net/" + e.Name() + "/wireless"); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// procWifi holds everything /proc/net/wireless reports per iface.
// `link` is the driver-internal quality score (typically out of 70); we
// renormalise to 0..100 in the snapshot.
type procWifi struct {
	link, signal float64
	linkMax      int
	retries      uint64
	beaconLoss   uint64
}

// readWireless parses /proc/net/wireless. Layout (kernel docs):
//
//	Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
//	 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
//	 wlan0: 0000   55.  -55.  -256        0      0      0      0      0        0
//
// fields[0] status, fields[1] link, fields[2] level, fields[3] noise,
// fields[7] retries, fields[9] missed-beacon. Driver-dependent.
func readWireless() (map[string]procWifi, error) {
	f, err := os.Open("/proc/net/wireless")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]procWifi{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "" || strings.ContainsAny(iface, "- |") {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 3 {
			continue
		}
		var p procWifi
		if v, err := strconv.ParseFloat(strings.TrimSuffix(fields[1], "."), 64); err == nil {
			p.link = v
			// Drivers commonly cap link quality at 70; renormalise to %
			// downstream when we know the max. 70 is a safe upper bound
			// for both `iwl*` and `ath*` families.
			p.linkMax = 70
			if p.link > 70 {
				p.linkMax = 100
			}
		}
		level := strings.TrimSuffix(fields[2], ".")
		p.signal, _ = strconv.ParseFloat(level, 64)
		if len(fields) >= 8 {
			p.retries, _ = strconv.ParseUint(fields[7], 10, 64)
		}
		if len(fields) >= 10 {
			p.beaconLoss, _ = strconv.ParseUint(fields[9], 10, 64)
		}
		out[iface] = p
	}
	return out, sc.Err()
}

// iwBinaryAvailable caches the lookup so we only stat $PATH once per
// process even when the collector is called every few seconds.
var (
	iwAvailableOnce sync.Once
	iwAvailable     bool
)

func iwBinaryAvailable() bool {
	iwAvailableOnce.Do(func() {
		if _, err := exec.LookPath("iw"); err == nil {
			iwAvailable = true
		}
	})
	return iwAvailable
}

// runIW runs `iw dev <iface> <sub>` with a short timeout and returns
// stdout. Empty string on error — the caller treats absence as
// "no data" rather than a hard failure.
func runIW(iface, sub string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iw", "dev", iface, sub).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// `iw dev <iface> info` output:
//
//	Interface wlan0
//	        ifindex 3
//	        addr aa:bb:cc:dd:ee:ff
//	        ssid MySSID
//	        type managed
//	        wiphy 0
//	        channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
//	        txpower 22.00 dBm
var (
	reChannel  = regexp.MustCompile(`channel\s+(\d+)\s+\((\d+)\s+MHz\).*width:\s*(\d+)\s*MHz`)
	reTXPower  = regexp.MustCompile(`txpower\s+([\d.]+)\s+dBm`)
	reType     = regexp.MustCompile(`(?m)^\s*type\s+(\S+)`)
	reSSIDInfo = regexp.MustCompile(`(?m)^\s*ssid\s+(.+)$`)
)

func parseIWInfo(iface string, s *WiFiSnapshot) {
	out := runIW(iface, "info")
	if out == "" {
		return
	}
	if m := reChannel.FindStringSubmatch(out); m != nil {
		s.Channel, _ = strconv.Atoi(m[1])
		s.Frequency, _ = strconv.Atoi(m[2])
		s.ChannelWMHz, _ = strconv.Atoi(m[3])
	}
	if m := reTXPower.FindStringSubmatch(out); m != nil {
		s.TXPower, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reType.FindStringSubmatch(out); m != nil {
		s.PhyType = m[1]
	}
	if s.SSID == "" {
		if m := reSSIDInfo.FindStringSubmatch(out); m != nil {
			s.SSID = strings.TrimSpace(m[1])
		}
	}
}

// `iw dev <iface> link` output (when associated):
//
//	Connected to aa:bb:cc:dd:ee:ff (on wlan0)
//	        SSID: MySSID
//	        freq: 5180
//	        signal: -45 dBm
//	        rx bitrate: 433.3 MBit/s
//	        tx bitrate: 390.0 MBit/s
//
// "Not connected." for an unassociated radio.
var (
	reConnected  = regexp.MustCompile(`(?i)Connected\s+to\s+([0-9a-f:]{17})`)
	reSSIDLink   = regexp.MustCompile(`(?m)^\s*SSID:\s+(.+)$`)
	reFreqLink   = regexp.MustCompile(`(?m)^\s*freq:\s+(\d+)`)
	reSignalLink = regexp.MustCompile(`(?m)^\s*signal:\s+(-?\d+)`)
	reTXBitrate  = regexp.MustCompile(`(?m)^\s*tx bitrate:\s+([\d.]+)\s+MBit/s`)
	reRXBitrate  = regexp.MustCompile(`(?m)^\s*rx bitrate:\s+([\d.]+)\s+MBit/s`)
)

func parseIWLink(iface string, s *WiFiSnapshot) {
	out := runIW(iface, "link")
	if out == "" || strings.Contains(out, "Not connected") {
		return
	}
	if m := reConnected.FindStringSubmatch(out); m != nil {
		s.BSSID = strings.ToLower(m[1])
	}
	if m := reSSIDLink.FindStringSubmatch(out); m != nil {
		s.SSID = strings.TrimSpace(m[1])
	}
	if m := reFreqLink.FindStringSubmatch(out); m != nil {
		s.Frequency, _ = strconv.Atoi(m[1])
	}
	if m := reSignalLink.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		if v != 0 {
			s.Signal = v
		}
	}
	if m := reTXBitrate.FindStringSubmatch(out); m != nil {
		s.TXBitrateM, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reRXBitrate.FindStringSubmatch(out); m != nil {
		s.RXBitrateM, _ = strconv.ParseFloat(m[1], 64)
	}
}

// `iw dev <iface> station dump` output (one block per associated peer):
//
//	Station aa:bb:cc:dd:ee:ff (on wlan0)
//	        rx bytes:       12345
//	        rx packets:     50
//	        tx bytes:       67890
//	        tx packets:     100
//	        tx retries:     5
//	        tx failed:      0
//	        beacon loss:    0
//	        signal:         -45 dBm
//	        signal avg:     -46 dBm
//	        tx bitrate:     390.0 MBit/s
//	        rx bitrate:     433.3 MBit/s
//	        connected time: 12345 seconds
//
// In client (managed) mode there's exactly one station (the AP), so
// we just read the first block. In AP / monitor mode multiple stations
// are possible; we still surface the first to keep the schema simple.
var (
	reRxBytes      = regexp.MustCompile(`(?m)^\s*rx bytes:\s+(\d+)`)
	reTxBytes      = regexp.MustCompile(`(?m)^\s*tx bytes:\s+(\d+)`)
	reRxPackets    = regexp.MustCompile(`(?m)^\s*rx packets:\s+(\d+)`)
	reTxPackets    = regexp.MustCompile(`(?m)^\s*tx packets:\s+(\d+)`)
	reTxRetries    = regexp.MustCompile(`(?m)^\s*tx retries:\s+(\d+)`)
	reTxFailed     = regexp.MustCompile(`(?m)^\s*tx failed:\s+(\d+)`)
	reBeaconLoss   = regexp.MustCompile(`(?m)^\s*beacon loss:\s+(\d+)`)
	reSignalAvg    = regexp.MustCompile(`(?m)^\s*signal avg:\s+(-?\d+)`)
	reConnectedTm  = regexp.MustCompile(`(?m)^\s*connected time:\s+(\d+)\s+seconds`)
	reStationNoise = regexp.MustCompile(`(?m)^\s*noise:\s+(-?\d+)`)
)

func parseIWStation(iface string, s *WiFiSnapshot) {
	out := runIW(iface, "station dump")
	if out == "" {
		return
	}
	if m := reRxBytes.FindStringSubmatch(out); m != nil {
		s.RxBytes, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reTxBytes.FindStringSubmatch(out); m != nil {
		s.TxBytes, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reRxPackets.FindStringSubmatch(out); m != nil {
		s.RxPackets, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reTxPackets.FindStringSubmatch(out); m != nil {
		s.TxPackets, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reTxRetries.FindStringSubmatch(out); m != nil {
		s.Retries, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reTxFailed.FindStringSubmatch(out); m != nil {
		s.TxFailed, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reBeaconLoss.FindStringSubmatch(out); m != nil {
		s.BeaconLoss, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if m := reSignalAvg.FindStringSubmatch(out); m != nil {
		s.SignalAvg, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reConnectedTm.FindStringSubmatch(out); m != nil {
		secs, _ := strconv.ParseInt(m[1], 10, 64)
		s.ConnectedAt = time.Now().Add(-time.Duration(secs) * time.Second)
	}
	if m := reStationNoise.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		if v != 0 {
			s.Noise = v
		}
	}
}

// freqToChannel translates a 2.4 / 5 / 6 GHz channel-centre frequency
// (MHz) back to the IEEE channel number. We only need the common
// channel-spacing rules, not the full IEEE 802.11 spec — the values
// outside these ranges fall back to 0 ("unknown channel").
func freqToChannel(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq < 2484:
		return (freq - 2407) / 5
	case freq >= 5160 && freq <= 5885:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		// 6 GHz band (Wi-Fi 6E) — channels 1..233, spacing 5 MHz.
		return (freq - 5950) / 5
	}
	return 0
}

func freqToBand(freq int) string {
	switch {
	case freq < 2500:
		return "2.4 GHz"
	case freq < 5900:
		return "5 GHz"
	default:
		return "6 GHz"
	}
}
