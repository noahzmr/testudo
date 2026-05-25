//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// LLDPListener passively listens for IEEE 802.1AB Link Layer Discovery
// Protocol frames on every up, non-loopback interface and decodes the
// TLV stream into Inventory records. LLDP is the highest-signal way to
// identify directly-connected switches, routers, IP phones and APs —
// the neighbour announces its own chassis, system name, description and
// capabilities. No probe traffic is generated.
//
// Requires CAP_NET_RAW (AF_PACKET / SOCK_RAW). On systems without the
// capability the listener silently no-ops; the rest of discovery is
// unaffected.
type LLDPListener struct {
	Inventory *Inventory
}

// ethPLLDP is the IEEE-assigned ethertype for LLDP, in network byte order
// as required by AF_PACKET socket() / bind().
const ethPLLDP = 0x88cc

// Run opens one AF_PACKET socket per interface and decodes incoming LLDP
// frames until ctx is cancelled. Each interface gets its own goroutine so
// a stuck/erroring iface can't starve the others.
func (l *LLDPListener) Run(ctx context.Context) error {
	if l == nil || l.Inventory == nil {
		return nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip interfaces that obviously can't carry LLDP frames from
		// a switch (point-to-point tunnels, virtual wires).
		if ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		wg.Add(1)
		go func(ifi net.Interface) {
			defer wg.Done()
			l.listenOn(ctx, ifi)
		}(ifi)
	}
	wg.Wait()
	return nil
}

// listenOn opens a packet socket bound to ifi filtering for ethertype
// 0x88cc and dispatches every received frame to decodeLLDPDU. It returns
// when ctx is done or when the socket errors fatally.
func (l *LLDPListener) listenOn(ctx context.Context, ifi net.Interface) {
	// htons(ethPLLDP) — the kernel expects network byte order on this arg.
	proto := uint16((ethPLLDP&0xff)<<8) | uint16(ethPLLDP>>8)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		// Most common reason: no CAP_NET_RAW. Soft-fail per interface.
		return
	}
	defer unix.Close(fd)
	sll := &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		return
	}
	// Wake from Recvfrom every 2s so we can honour ctx cancellation.
	tv := unix.Timeval{Sec: 2, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 1600)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN/EWOULDBLOCK from the timeout — keep looping.
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return
		}
		if n < 14 {
			continue
		}
		// Verify ethertype — kernel already filtered by proto bind, but
		// double-checking is cheap and avoids surprises on VLAN-tagged
		// frames that some drivers expose raw.
		etype := binary.BigEndian.Uint16(buf[12:14])
		payload := buf[14:n]
		if etype == 0x8100 && n >= 18 {
			// 802.1Q VLAN tag — skip 4 bytes and re-read ethertype.
			etype = binary.BigEndian.Uint16(buf[16:18])
			payload = buf[18:n]
		}
		if etype != ethPLLDP {
			continue
		}
		dev := decodeLLDPDU(payload)
		if dev.LLDPChassisID == "" && dev.SysName == "" {
			continue
		}
		dev.Iface = ifi.Name
		dev.LLDPLocalIface = ifi.Name
		dev.Source = "lldp"

		// Pick an IP for inventory keying. Management address > L3 hint
		// from any addr the neighbour advertised. If none, fall back to
		// the LLDP chassis ID itself so we still record the device under
		// a stable key — these rows surface in a separate "L2 neighbours"
		// pane in the TUI.
		if len(dev.LLDPMgmtAddrs) > 0 {
			dev.IP = dev.LLDPMgmtAddrs[0]
		} else {
			dev.IP = "lldp:" + dev.LLDPChassisID
		}
		dev.DeviceType = classifyFromLLDPCaps(dev.LLDPCapabilities)
		l.Inventory.Observe(dev)
	}
}

// decodeLLDPDU walks the TLV stream of an LLDPDU payload and fills the
// observable fields of a Device. The TLV header is 16 bits big-endian:
// top 7 bits = type, bottom 9 bits = length.
func decodeLLDPDU(p []byte) Device {
	var d Device
	off := 0
	for off+2 <= len(p) {
		hdr := binary.BigEndian.Uint16(p[off : off+2])
		tlvType := int(hdr >> 9)
		tlvLen := int(hdr & 0x01ff)
		off += 2
		if off+tlvLen > len(p) {
			break
		}
		v := p[off : off+tlvLen]
		off += tlvLen
		switch tlvType {
		case 0:
			// End of LLDPDU.
			return d
		case 1:
			d.LLDPChassisID = formatLLDPID(v, true)
			if mac := extractMAC(v, true); mac != "" {
				d.MAC = mac
				if vd := vendorFor(mac); vd != "" {
					d.Vendor = vd
				}
			}
		case 2:
			d.LLDPPortID = formatLLDPID(v, false)
		case 3:
			// TTL — ignored.
		case 4:
			d.LLDPPortDesc = string(v)
		case 5:
			d.SysName = string(v)
			d.Hostname = string(v)
		case 6:
			d.SysDescr = string(v)
		case 7:
			if len(v) >= 4 {
				caps := binary.BigEndian.Uint16(v[0:2])
				enabled := binary.BigEndian.Uint16(v[2:4])
				d.LLDPCapabilities = decodeLLDPCaps(caps & enabled)
			}
		case 8:
			if mgmt := decodeMgmtAddr(v); mgmt != "" {
				d.LLDPMgmtAddrs = append(d.LLDPMgmtAddrs, mgmt)
			}
		}
	}
	return d
}

// formatLLDPID renders an LLDP Chassis-ID or Port-ID TLV value. The first
// byte is the subtype; the rest is the identifier in a subtype-specific
// encoding. MAC and network-address subtypes get pretty-printed, the rest
// are returned as UTF-8 strings (with hex fallback for non-printable).
func formatLLDPID(v []byte, chassis bool) string {
	if len(v) < 2 {
		return ""
	}
	subtype := v[0]
	body := v[1:]
	switch subtype {
	case 4: // chassis: MAC | port: MAC
		return formatMAC(body)
	case 5: // network address
		if len(body) >= 1 {
			af := body[0]
			addr := body[1:]
			switch af {
			case 1: // IPv4
				if len(addr) == 4 {
					return net.IP(addr).String()
				}
			case 2: // IPv6
				if len(addr) == 16 {
					return net.IP(addr).String()
				}
			}
		}
	}
	// 1=chassis-comp, 2=if-alias, 3=port-comp, 6=if-name, 7=locally-assigned
	if isPrintable(body) {
		return string(body)
	}
	return hex.EncodeToString(body)
}

// extractMAC returns a colon-formatted MAC iff the TLV value is a
// MAC-subtype identifier (subtype byte == 4, six bytes of address).
func extractMAC(v []byte, chassis bool) string {
	if len(v) < 7 || v[0] != 4 {
		return ""
	}
	return formatMAC(v[1:7])
}

// decodeMgmtAddr extracts the IP from an LLDP Management Address TLV. The
// TLV body layout: addrLen, addrSubtype, address[addrLen-1], ifSubtype,
// ifNumber(4), oidLen, oid[oidLen]. We only care about address.
func decodeMgmtAddr(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	addrLen := int(v[0])
	if addrLen < 2 || len(v) < 1+addrLen {
		return ""
	}
	subtype := v[1]
	addr := v[2 : 1+addrLen]
	switch subtype {
	case 1: // IPv4
		if len(addr) == 4 {
			return net.IP(addr).String()
		}
	case 2: // IPv6
		if len(addr) == 16 {
			return net.IP(addr).String()
		}
	}
	return ""
}

// decodeLLDPCaps maps the system-capabilities bitmask into the human
// labels used by the UI. Bits are defined by IANA-LLDP-MIB.
func decodeLLDPCaps(mask uint16) []string {
	labels := []struct {
		bit  uint16
		name string
	}{
		{1 << 0, "other"},
		{1 << 1, "repeater"},
		{1 << 2, "bridge"},
		{1 << 3, "wlan-ap"},
		{1 << 4, "router"},
		{1 << 5, "telephone"},
		{1 << 6, "docsis"},
		{1 << 7, "station"},
		{1 << 8, "cvlan"},
		{1 << 9, "svlan"},
		{1 << 10, "tpmr"},
	}
	out := make([]string, 0, 3)
	for _, l := range labels {
		if mask&l.bit != 0 {
			out = append(out, l.name)
		}
	}
	return out
}

// classifyFromLLDPCaps picks a single coarse DeviceType label from the set
// of LLDP system capabilities, preferring more specific roles over generic
// ones (router > switch > AP > phone > station).
func classifyFromLLDPCaps(caps []string) string {
	set := map[string]bool{}
	for _, c := range caps {
		set[c] = true
	}
	switch {
	case set["router"]:
		return "router"
	case set["bridge"]:
		return "switch"
	case set["wlan-ap"]:
		return "ap"
	case set["telephone"]:
		return "phone"
	case set["station"]:
		return "workstation"
	}
	return ""
}

// formatMAC renders six bytes as "aa:bb:cc:dd:ee:ff".
func formatMAC(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// isPrintable returns true when v looks like a UTF-8 string (no NULs, no
// control bytes outside tab/LF/CR). LLDP string TLVs are usually plain
// ASCII; vendor extensions occasionally smuggle binary, hence the check.
func isPrintable(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c == 0 {
			return false
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return strings.ToValidUTF8(string(v), "") == string(v)
}

