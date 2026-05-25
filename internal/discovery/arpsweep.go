//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ARP sweep - proactively populate /proc/net/arp by broadcasting ARP
// requests for every host in every directly-connected IPv4 subnet. ICMP
// echo gets dropped by a long tail of consumer devices (Windows firewall
// defaults, IoT silence, "ping-shy" servers); ARP, by contrast, has to
// answer for the host to be reachable at all on the LAN. This is the
// single biggest win for "where are all my devices?" detection on a
// typical office or home network.
//
// Requires CAP_NET_RAW (AF_PACKET / SOCK_RAW). Soft-fails per interface
// when the cap is missing.

const ethPARP = 0x0806

// arpSweepAll sends a broadcast ARP request to every host in every
// directly-connected IPv4 subnet on every interface, then listens briefly
// for replies. Caps the sweep at /20 (4096 hosts) so a misconfigured /16
// doesn't generate 64k frames in one tick.
func (s *Scanner) arpSweepAll(ctx context.Context, maxSubnetBits int) {
	if s == nil || s.Inventory == nil {
		return
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if len(ifi.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits-ones > maxSubnetBits {
				continue
			}
			wg.Add(1)
			go func(ifi net.Interface, srcIP net.IP, sub *net.IPNet) {
				defer wg.Done()
				s.arpSweepOne(ctx, ifi, srcIP, sub)
			}(ifi, ipn.IP.To4(), ipn)
		}
	}
	wg.Wait()
}

// arpSweepOne fires one ARP request per host on ifi, then drains replies
// for up to 3 seconds. Sender and receiver share the same AF_PACKET
// socket so we don't miss replies that race the last few requests.
func (s *Scanner) arpSweepOne(ctx context.Context, ifi net.Interface, srcIP net.IP, sub *net.IPNet) {
	// htons(0x0806). The kernel expects network byte order on this arg.
	proto := uint16((ethPARP&0xff)<<8) | uint16(ethPARP>>8)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return
	}
	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// Reply reader. Lives until deadline; logs every (sender-IP, sender-MAC)
	// it sees on this iface. Buffer is large enough for VLAN-tagged ARP.
	var rwg sync.WaitGroup
	rwg.Add(1)
	deadline := time.Now().Add(3 * time.Second)
	go func() {
		defer rwg.Done()
		buf := make([]byte, 1500)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					continue
				}
				return
			}
			if n < 42 {
				continue
			}
			s.recordARPReply(buf[:n], ifi.Name)
		}
	}()

	// Sender. Iterate every host in the subnet except network/broadcast,
	// staggering by 1ms so we don't bury the local NIC's tx queue and
	// drop our own outbound frames on slower hardware.
	base := sub.IP.Mask(sub.Mask).To4()
	ones, bits := sub.Mask.Size()
	count := 1 << (bits - ones)
	srcHW := ifi.HardwareAddr
	for i := 1; i < count-1; i++ {
		target := dupIP(base)
		incIP(target, i)
		// Skip our own address.
		if target.Equal(srcIP) {
			continue
		}
		frame := buildARPRequest(srcHW, srcIP, target)
		dst := &unix.SockaddrLinklayer{
			Protocol: proto,
			Ifindex:  ifi.Index,
			Halen:    6,
			Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		}
		_ = unix.Sendto(fd, frame, 0, dst)
		time.Sleep(time.Millisecond)
		if ctx.Err() != nil {
			break
		}
	}
	rwg.Wait()
}

// buildARPRequest builds a 42-byte Ethernet + ARP request frame asking
// "who has tgtIP? tell src". Destination MAC is broadcast.
func buildARPRequest(srcHW net.HardwareAddr, srcIP, tgtIP net.IP) []byte {
	frame := make([]byte, 42)
	// Ethernet header.
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcHW)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)
	// ARP packet.
	binary.BigEndian.PutUint16(frame[14:16], 1)      // HW type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // proto type: IPv4
	frame[18] = 6                                    // HW size
	frame[19] = 4                                    // proto size
	binary.BigEndian.PutUint16(frame[20:22], 1)      // op: request
	copy(frame[22:28], srcHW)
	copy(frame[28:32], srcIP.To4())
	// target HW left zero; that's the convention for a request.
	copy(frame[38:42], tgtIP.To4())
	return frame
}

// recordARPReply parses an inbound ARP reply frame and records the
// (sender-IP, sender-MAC) pair in the inventory. Ignores anything that
// isn't an ARP reply on IPv4/Ethernet.
func (s *Scanner) recordARPReply(buf []byte, ifaceName string) {
	if len(buf) < 42 {
		return
	}
	if binary.BigEndian.Uint16(buf[12:14]) != ethPARP {
		return
	}
	if binary.BigEndian.Uint16(buf[14:16]) != 1 || binary.BigEndian.Uint16(buf[16:18]) != 0x0800 {
		return
	}
	op := binary.BigEndian.Uint16(buf[20:22])
	if op != 2 {
		return
	}
	senderHW := net.HardwareAddr(buf[22:28]).String()
	senderIP := net.IP(buf[28:32]).String()
	if senderHW == "00:00:00:00:00:00" || senderIP == "0.0.0.0" {
		return
	}
	s.Inventory.Observe(Device{
		IP: senderIP, MAC: senderHW, Iface: ifaceName,
		Source: "arp-sweep",
		Vendor: vendorFor(senderHW),
	})
}
