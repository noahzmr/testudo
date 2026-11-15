package frrstage

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// bgpPeer is the smallest BGP speaker that can hold a session with a real
// router: it answers the OPEN, keeps the session alive, announces one IPv4
// prefix and records the prefixes it is sent. It exists so the routing test
// needs no second routing daemon.
type bgpPeer struct {
	as       uint16
	routerID net.IP
	announce *net.IPNet
	nextHop  net.IP

	mu          sync.Mutex
	received    map[string]bool
	established bool
}

func (p *bgpPeer) got(prefix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.received[prefix]
}

func msg(typ byte, body []byte) []byte {
	out := make([]byte, 19, 19+len(body))
	for i := 0; i < 16; i++ {
		out[i] = 0xff
	}
	binary.BigEndian.PutUint16(out[16:], uint16(19+len(body)))
	out[18] = typ
	return append(out, body...)
}

func prefixBytes(n *net.IPNet) []byte {
	ones, _ := n.Mask.Size()
	return append([]byte{byte(ones)}, n.IP.To4()[:(ones+7)/8]...)
}

// serve handles one session on conn.
func (p *bgpPeer) serve(conn net.Conn) {
	defer conn.Close()
	read := func() (byte, []byte, error) {
		hdr := make([]byte, 19)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return 0, nil, err
		}
		body := make([]byte, int(binary.BigEndian.Uint16(hdr[16:]))-19)
		_, err := io.ReadFull(conn, body)
		return hdr[18], body, err
	}
	// OPEN: version 4, our AS, hold time 90, router id, no optional parameters.
	open := []byte{4, 0, 0, 0, 90}
	binary.BigEndian.PutUint16(open[1:], p.as)
	open = append(append(open, p.routerID.To4()...), 0)
	if _, err := conn.Write(msg(1, open)); err != nil {
		return
	}
	if typ, _, err := read(); err != nil || typ != 1 {
		return
	}
	conn.Write(msg(4, nil)) // KEEPALIVE confirms the OPEN

	// UPDATE: ORIGIN igp, AS_PATH [our AS], NEXT_HOP, then the prefix.
	attrs := []byte{0x40, 1, 1, 0}
	attrs = append(attrs, 0x40, 2, 4, 2, 1, byte(p.as>>8), byte(p.as))
	attrs = append(append(attrs, 0x40, 3, 4), p.nextHop.To4()...)
	update := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(update[2:], uint16(len(attrs)))
	update = append(append(update, attrs...), prefixBytes(p.announce)...)

	go func() {
		for range time.Tick(10 * time.Second) {
			if _, err := conn.Write(msg(4, nil)); err != nil {
				return
			}
		}
	}()
	for {
		typ, body, err := read()
		if err != nil {
			return
		}
		switch typ {
		case 4: // the router's KEEPALIVE: the session is up
			p.mu.Lock()
			first := !p.established
			p.established = true
			p.mu.Unlock()
			if first {
				conn.Write(msg(2, update))
			}
		case 2:
			// withdrawn routes, path attributes, then the announced prefixes
			if len(body) < 4 {
				continue
			}
			wlen := int(binary.BigEndian.Uint16(body))
			alen := int(binary.BigEndian.Uint16(body[2+wlen:]))
			nlri := body[4+wlen+alen:]
			for len(nlri) > 0 {
				bits := int(nlri[0])
				n := (bits + 7) / 8
				ip := make(net.IP, 4)
				copy(ip, nlri[1:1+n])
				p.mu.Lock()
				p.received[fmt.Sprintf("%s/%d", ip, bits)] = true
				p.mu.Unlock()
				nlri = nlri[1+n:]
			}
		case 3:
			return // NOTIFICATION
		}
	}
}

// listen accepts sessions on ln until it is closed.
func (p *bgpPeer) listen(ln net.Listener) {
	p.received = map[string]bool{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go p.serve(conn)
	}
}
