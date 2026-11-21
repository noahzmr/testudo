package model

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
)

// FieldError is one validation failure, addressed by the JSON field path.
type FieldError struct {
	Field   string `json:"field"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// ValidationError collects every failure of one object.
type ValidationError struct {
	Kind   Kind         `json:"kind"`
	ID     string       `json:"id,omitempty"`
	Fields []FieldError `json:"fields"`
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return fmt.Sprintf("%s invalid: %s", e.Kind, strings.Join(parts, "; "))
}

var (
	objNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	ifNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$`)
	labelRe     = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	rateRe      = regexp.MustCompile(`^[1-9][0-9]{0,8}/(second|minute|hour|day)$`)
	communityRe = regexp.MustCompile(`^([0-9]{1,5}:[0-9]{1,5}|[0-9]{1,10}:[0-9]{1,10}:[0-9]{1,10}|no-export|no-advertise|local-as)$`)
	permRe      = regexp.MustCompile(`^(\*|[a-z][a-z_]{0,30}):(read|write)(@(site|node):[0-9a-f-]{36})?$`)
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// CustomRules are the validators this package adds to the library's own.
// The schema generator uses the descriptions; a test keeps both in step.
var CustomRules = map[string]struct {
	Description string
	Pattern     string // JSON Schema pattern, when one expresses the rule
	check       func(string) bool
}{
	"objname":          {"letters, digits, dot, dash, underscore; at most 63", objNameRe.String(), objNameRe.MatchString},
	"ifname":           {"kernel interface name, at most 15 characters", ifNameRe.String(), ifNameRe.MatchString},
	"scope":            {"global, site:<uuid> or node:<uuid>", `^(global|(site|node):[0-9a-f-]{36})$`, validScope},
	"cidr_or_ip":       {"IP address or network in CIDR form", "", validCIDROrIP},
	"portrange":        {"port or port range, 1-65535", `^[0-9]{1,5}(-[0-9]{1,5})?$`, validPortRange},
	"duration":         {"duration such as 30s, 5m or 1h", `^([0-9]+(\.[0-9]+)?(ms|s|m|h))+$`, validDuration},
	"ratelimit":        {"rate such as 10/second", rateRe.String(), rateRe.MatchString},
	"wgkey":            {"WireGuard key: 32 bytes, base64", `^[A-Za-z0-9+/]{43}=$`, validWGKey},
	"fqdn_or_wildcard": {"host name, optionally with a leading *. label", "", validFQDNOrWildcard},
	"hostport":         {"host:port; an IPv6 address goes in brackets", "", validHostPort},
	"community":        {"BGP community (standard, large or well-known)", communityRe.String(), communityRe.MatchString},
	"ospfarea":         {"OSPF area as dotted quad or number", "", validOSPFArea},
	"permission":       {"<area>:read or <area>:write; area may be *; @site:<id> or @node:<id> limits it to that site or node", permRe.String(), permRe.MatchString},
	"mac":              {"hardware address such as 52:54:00:12:34:56", `^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`, validMAC},
	"duid":             {"DHCPv6 DUID as colon-separated hex bytes", `^([0-9A-Fa-f]{2}:){1,129}[0-9A-Fa-f]{2}$`, duidRe.MatchString},
	"iprange":          {"address range such as 192.168.1.100-192.168.1.199, or a network", "", validIPRange},
	"dnsupstream":      {"IP address, optionally @port and #TLS name", "", validDNSUpstream},
	"hostorip":         {"host name or IP address", "", validHostOrIP},
}

var duidRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){1,129}[0-9A-Fa-f]{2}$`)

var macRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func validMAC(s string) bool { return macRe.MatchString(s) }

// validIPRange accepts first-last of one family, first not after last, or
// a network in CIDR form.
func validIPRange(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}
	x, y := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if x == nil || y == nil || (x.To4() == nil) != (y.To4() == nil) {
		return false
	}
	if x4 := x.To4(); x4 != nil {
		x, y = x4, y.To4()
	}
	return bytes.Compare(x, y) <= 0
}

// validDNSUpstream accepts an address with an optional @port and #name
// (the name a TLS upstream's certificate has to carry).
func validDNSUpstream(s string) bool {
	addr, name, hasName := strings.Cut(s, "#")
	if hasName && !validFQDNOrWildcard(name) {
		return false
	}
	host, port, hasPort := strings.Cut(addr, "@")
	if hasPort {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return false
		}
	}
	return net.ParseIP(host) != nil
}

func validHostOrIP(s string) bool {
	return net.ParseIP(s) != nil || (!strings.HasPrefix(s, "*") && validFQDNOrWildcard(s))
}

func validScope(s string) bool {
	if s == string(ScopeGlobal) {
		return true
	}
	level, id, ok := strings.Cut(s, ":")
	return ok && (level == "site" || level == "node") && uuidRe.MatchString(id)
}

func validCIDROrIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func validPortRange(s string) bool {
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil || a < 1 || a > 65535 {
		return false
	}
	if !isRange {
		return true
	}
	b, err := strconv.Atoi(hi)
	return err == nil && b >= a && b <= 65535
}

func validDuration(s string) bool {
	d, err := time.ParseDuration(s)
	return err == nil && d > 0
}

func validWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func validFQDNOrWildcard(s string) bool {
	s = strings.TrimPrefix(s, "*.")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// validHostPort accepts name:port, 192.0.2.1:port and [2001:db8::1]:port.
func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	if strings.HasPrefix(s, "[") {
		ip := net.ParseIP(host)
		return ip != nil && ip.To4() == nil
	}
	return net.ParseIP(host) != nil || (!strings.HasPrefix(host, "*") && validFQDNOrWildcard(host))
}

func validOSPFArea(s string) bool {
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return true
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

var validate = sync.OnceValue(func() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		return name
	})
	for tag, rule := range CustomRules {
		check := rule.check
		if err := v.RegisterValidation(tag, func(fl validator.FieldLevel) bool {
			return check(fl.Field().String())
		}); err != nil {
			panic(err)
		}
	}
	return v
})

// Validate checks one object against its struct tags and the scope levels
// its kind allows. It does not look at other objects; cross-object checks
// live with the store.
func Validate(e Entity) error {
	out := &ValidationError{Kind: e.Kind(), ID: e.GetMeta().ID}
	if err := validate().Struct(e); err != nil {
		var verrs validator.ValidationErrors
		if !errors.As(err, &verrs) {
			return err
		}
		for _, fe := range verrs {
			// Namespace is "Type.field.sub"; drop the type and the
			// embedded Meta so the path matches the JSON document.
			_, path, _ := strings.Cut(fe.Namespace(), ".")
			path = strings.TrimPrefix(path, "Meta.")
			msg := "fails " + fe.Tag()
			if fe.Param() != "" {
				msg += "=" + fe.Param()
			}
			if r, ok := CustomRules[fe.Tag()]; ok {
				msg = "expected " + r.Description
			}
			out.Fields = append(out.Fields, FieldError{Field: path, Rule: fe.Tag(), Message: msg})
		}
	}
	if info, ok := Lookup(string(e.Kind())); ok {
		m := e.GetMeta()
		if m.Scope != "" && validScope(string(m.Scope)) && !slices.Contains(info.Scopes, m.Scope.Level()) {
			out.Fields = append(out.Fields, FieldError{Field: "scope", Rule: "scope_level",
				Message: fmt.Sprintf("%s objects must be scoped to one of: %s", e.Kind(), strings.Join(info.Scopes, ", "))})
		}
		for i, o := range m.Overrides {
			for k := range o.Values {
				if slices.Contains(protectedFields, k) {
					out.Fields = append(out.Fields, FieldError{Field: fmt.Sprintf("overrides[%d].values.%s", i, k),
						Rule: "override_protected", Message: "this field cannot be overridden"})
				}
			}
		}
	}
	if len(out.Fields) == 0 {
		return nil
	}
	slices.SortFunc(out.Fields, func(a, b FieldError) int { return strings.Compare(a.Field+a.Rule, b.Field+b.Rule) })
	return out
}

var hostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

// ValidHostname reports whether s is a host name in RFC 1123 form, with an
// optional trailing dot.
func ValidHostname(s string) bool { return len(s) <= 253 && hostnameRe.MatchString(s) }
