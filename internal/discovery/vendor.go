package discovery

import (
	"strings"
	"sync"

	"github.com/endobit/oui"
)

// MACType classifies the administration scope of a MAC address. It's surfaced
// in the UI so randomized/private MACs (which carry no useful OUI) are flagged
// rather than shown as an unidentified vendor.
const (
	MACTypeGlobal     = "global"     // IEEE-assigned OUI - vendor lookup is meaningful
	MACTypeRandomized = "randomized" // locally administered (privacy/randomized MAC)
	MACTypeMulticast  = "multicast"  // group address - not a real host NIC
)

// vendorCache memoizes lookups keyed by the normalized 3-octet OUI prefix.
// oui.Vendor is itself a generated-map lookup, but caching the (prefix =>
// vendor) result also shortcuts the normalization on the hot ARP path.
var vendorCache sync.Map // string -> string

// vendorOverride maps OUI prefixes to friendlier labels than the raw IEEE
// registration name, or fills gaps the IEEE CSV labels poorly. Checked before
// the OUI database. Keep this list small and intentional.
var vendorOverride = map[string]string{
	"00:15:5D": "Microsoft Hyper-V",
	"00:50:56": "VMware",
	"00:1C:42": "Parallels",
	"08:00:27": "Oracle VirtualBox",
	"52:54:00": "QEMU/KVM",
}

// normalizeMAC canonicalizes a MAC string to upper-case colon-separated form
// ("AA:BB:CC:DD:EE:FF"). Accepts colon, hyphen, and Cisco dot notation. Returns
// "" if the input has no recognizable hex octets.
func normalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Strip the common separators, then re-group into octets.
	r := strings.NewReplacer("-", "", ":", "", ".", "")
	hex := strings.ToUpper(r.Replace(s))
	if len(hex) < 12 {
		return ""
	}
	hex = hex[:12]
	for i := 0; i < 12; i++ {
		c := hex[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}

// ouiPrefixOf returns the upper-case "AA:BB:CC" prefix of a normalized MAC, or
// "" if the address is too short.
func ouiPrefixOf(normMAC string) string {
	if len(normMAC) < 8 {
		return ""
	}
	return normMAC[:8]
}

// classifyMAC inspects the first octet's administration bits. The least
// significant bit of the first octet marks a multicast/group address; the
// next bit marks a locally administered address (the signature of a randomized
// or otherwise synthetic MAC). Globally unique IEEE-assigned MACs have both
// bits clear. Returns "" for an unparseable address.
func classifyMAC(mac string) string {
	norm := normalizeMAC(mac)
	if norm == "" {
		return ""
	}
	// First octet is norm[0:2].
	first := hexByte(norm[0], norm[1])
	switch {
	case first&0x01 != 0:
		return MACTypeMulticast
	case first&0x02 != 0:
		return MACTypeRandomized
	default:
		return MACTypeGlobal
	}
}

// hexByte decodes two upper-case hex characters into a byte. Callers pass
// validated input (from normalizeMAC), so unrecognized nibbles decode as 0.
func hexByte(hi, lo byte) byte {
	return nibble(hi)<<4 | nibble(lo)
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// vendorFor maps a MAC address to a vendor name using the full IEEE OUI
// registry (via github.com/endobit/oui). Locally administered / randomized and
// multicast addresses carry no meaningful OUI, so they resolve to "". Results
// are cached by OUI prefix.
func vendorFor(mac string) string {
	norm := normalizeMAC(mac)
	if norm == "" {
		return ""
	}
	prefix := ouiPrefixOf(norm)
	if prefix == "" {
		return ""
	}
	if v, ok := vendorCache.Load(prefix); ok {
		return v.(string)
	}
	vendor := lookupVendor(norm, prefix)
	vendorCache.Store(prefix, vendor)
	return vendor
}

// lookupVendor performs the uncached resolution: skip non-global MACs, prefer
// an explicit override, then fall back to the OUI database.
func lookupVendor(norm, prefix string) string {
	if classifyMAC(norm) != MACTypeGlobal {
		return ""
	}
	if v, ok := vendorOverride[prefix]; ok {
		return v
	}
	return oui.Vendor(norm)
}
