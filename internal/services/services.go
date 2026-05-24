// Package services maps well-known L4 ports to service names. The table is
// intentionally small and curated — IANA has ~6000 entries, but a TUI
// operator cares about the ~50 protocols that drive 95% of typical traffic.
// Extend at will; the lookup is O(1).
package services

import "strings"

// portKey combines proto and port for the map lookup.
type portKey struct {
	proto string // "tcp" or "udp"
	port  uint16
}

// catalog is the in-memory lookup table. Lower-case proto for normalisation.
var catalog = map[portKey]Service{
	// Well-known and high-traffic services.
	{"tcp", 22}:    {"SSH", true},
	{"tcp", 23}:    {"Telnet", false},
	{"tcp", 25}:    {"SMTP", false},
	{"tcp", 53}:    {"DNS", false},
	{"udp", 53}:    {"DNS", false},
	{"tcp", 67}:    {"DHCP", false},
	{"udp", 67}:    {"DHCP", false},
	{"udp", 68}:    {"DHCP", false},
	{"tcp", 80}:    {"HTTP", false},
	{"udp", 123}:   {"NTP", false},
	{"tcp", 143}:   {"IMAP", false},
	{"tcp", 161}:   {"SNMP", false},
	{"udp", 161}:   {"SNMP", false},
	{"tcp", 389}:   {"LDAP", false},
	{"tcp", 443}:   {"HTTPS", true},
	{"udp", 443}:   {"QUIC", true},
	{"tcp", 445}:   {"SMB", true},
	{"tcp", 465}:   {"SMTPS", true},
	{"udp", 514}:   {"Syslog", false},
	{"tcp", 587}:   {"SMTP-Sub", true},
	{"tcp", 636}:   {"LDAPS", true},
	{"tcp", 993}:   {"IMAPS", true},
	{"tcp", 995}:   {"POP3S", true},
	{"tcp", 1080}:  {"SOCKS", false},
	{"tcp", 1194}:  {"OpenVPN", true},
	{"udp", 1194}:  {"OpenVPN", true},
	{"udp", 1701}:  {"L2TP", false},
	{"tcp", 1723}:  {"PPTP", false},
	{"tcp", 1812}:  {"RADIUS-Auth", false},
	{"udp", 1812}:  {"RADIUS-Auth", false},
	{"tcp", 2049}:  {"NFS", false},
	{"tcp", 2375}:  {"Docker", false},
	{"tcp", 2376}:  {"Docker-TLS", true},
	{"tcp", 3000}:  {"Grafana", false},
	{"tcp", 3306}:  {"MySQL", false},
	{"tcp", 3389}:  {"RDP", true},
	{"tcp", 4789}:  {"VXLAN", false},
	{"udp", 4789}:  {"VXLAN", false},
	{"udp", 5060}:  {"SIP", false},
	{"tcp", 5060}:  {"SIP", false},
	{"udp", 5353}:  {"mDNS", false},
	{"tcp", 5432}:  {"PostgreSQL", false},
	{"tcp", 5601}:  {"Kibana", false},
	{"tcp", 6379}:  {"Redis", false},
	{"tcp", 8080}:  {"HTTP-Alt", false},
	{"tcp", 8443}:  {"HTTPS-Alt", true},
	{"tcp", 8086}:  {"InfluxDB", false},
	{"tcp", 9090}:  {"Prometheus", false},
	{"tcp", 9092}:  {"Kafka", false},
	{"tcp", 9200}:  {"Elastic", false},
	{"tcp", 9418}:  {"Git", false},
	{"udp", 51820}: {"WireGuard", true},
	{"udp", 51821}: {"WireGuard", true},
}

// Service holds metadata about a known port assignment.
type Service struct {
	Name      string // canonical short name
	Encrypted bool   // hint for the TUI to colour traffic
}

// Lookup returns service metadata for a port, or zero-value when unknown.
// proto is case-insensitive; only tcp/udp are recognised.
func Lookup(proto string, port uint16) Service {
	if svc, ok := catalog[portKey{strings.ToLower(proto), port}]; ok {
		return svc
	}
	return Service{}
}

// Name is a convenience that returns the service name or an empty string.
func Name(proto string, port uint16) string {
	return Lookup(proto, port).Name
}

// IsEncrypted reports whether the well-known service on (proto, port) is
// known to use encryption at the application layer (HTTPS, SSH, SMB, etc).
func IsEncrypted(proto string, port uint16) bool {
	return Lookup(proto, port).Encrypted
}
