package ipfix

import "net"

// netParseIPImpl is the only spot in the package that imports net.IP. The
// manager indirects through it so callers don't end up with an unused-net
// build error when they only want the types.
func netParseIPImpl(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
