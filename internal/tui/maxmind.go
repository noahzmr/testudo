package tui

import (
	"strings"

	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/integrations/maxmind"
)

// geoCellForFlow renders the "GEO/THREAT" cell for one flow. Picks the
// most-likely remote endpoint (B first, then A) and falls back to "-" when
// the enricher has nothing.
func geoCellForFlow(eng *engine.Engine, f flows.FlowStats) string {
	mm := eng.MaxMind()
	if mm == nil {
		return dimStyle.Render("-")
	}
	// Memory-cache only: the render loop must never block on a .mmdb read or
	// SQLite write. Misses are enqueued for async resolution and surface on a
	// later render tick once the background worker fills the cache.
	for _, ip := range []string{f.Key.B.IP, f.Key.A.IP} {
		if r, ok := mm.Peek(ip); ok && !r.Empty() {
			return renderGeoCell(r)
		}
		mm.Enqueue(ip)
	}
	return dimStyle.Render("-")
}

// geoCellForDevice renders the same cell for a device row.
func geoCellForDevice(d discovery.Device) string {
	if d.CountryISO == "" && d.ASN == 0 && d.ThreatLevel == "" {
		return dimStyle.Render("-")
	}
	return renderGeoCell(maxmind.Result{
		CountryISO:  d.CountryISO,
		ASN:         d.ASN,
		ASOrg:       d.ASOrg,
		ThreatLevel: d.ThreatLevel,
	})
}

// renderGeoCell formats a Result into the table cell: "CC AS12345 ⚠tor".
// The threat tag is colour-tinted so high-risk flows stand out at a glance.
func renderGeoCell(r maxmind.Result) string {
	parts := []string{}
	if r.CountryISO != "" {
		parts = append(parts, r.CountryISO)
	}
	if r.ASN != 0 {
		parts = append(parts, asNumberString(r.ASN))
	}
	if tag := threatTag(r); tag != "" {
		parts = append(parts, tag)
	}
	if len(parts) == 0 {
		return dimStyle.Render("-")
	}
	return strings.Join(parts, " ")
}

func asNumberString(asn uint) string {
	return "AS" + uintToString(asn)
}

func uintToString(v uint) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// threatTag returns a colourised badge for the most concerning anonymity
// flag set on r. Empty when r carries no anonymity signal.
func threatTag(r maxmind.Result) string {
	switch {
	case r.IsTor:
		return errStyle.Render("⚠tor")
	case r.IsResidProxy:
		return errStyle.Render("⚠proxy")
	case r.IsVPN:
		return warnStyle.Render("⚠vpn")
	case r.IsPublicProxy:
		return warnStyle.Render("⚠proxy")
	case r.IsAnonymous:
		return warnStyle.Render("⚠anon")
	case r.IsHosting:
		return dimStyle.Render("host")
	}
	return ""
}
