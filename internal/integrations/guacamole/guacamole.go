// Package guacamole helps the TUI/Web UI hand off to an Apache Guacamole
// instance. We don't embed a Guacamole client (that would mean a full RDP/
// SSH stack + Java RDP gateway); instead we construct a deep-link URL that
// the operator's browser opens against their existing Guacamole deployment.
package guacamole

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// LaunchSpec describes a one-shot connection that should be opened in a
// running Guacamole instance.
type LaunchSpec struct {
	Protocol string // "ssh" | "rdp" | "vnc"
	Host     string
	Port     uint16
	Username string
}

// BuildURL renders a Guacamole "#/client/<base64-of-id-type-name>" URL.
// Guacamole's URL contract uses base64(uri-safe) of a NULL-separated tuple.
// baseURL is the Guacamole installation root, e.g. "https://guac.example.com".
// connID is the configured Guacamole connection identifier - Testudo
// doesn't auto-create connections; the operator must have one set up.
//
// Returns ErrNoBase when baseURL is empty so callers can degrade gracefully.
func BuildURL(baseURL, connID string, spec LaunchSpec) (string, error) {
	if baseURL == "" {
		return "", ErrNoBase
	}
	if connID == "" {
		// Compose a synthetic identifier from the spec so the URL is at
		// least clickable for diagnosis; Guacamole will respond with 404.
		connID = spec.Host
	}
	// Guacamole connection client URL format: base + "/#/client/" + base64(id\0c\0name)
	// We use "c" as type (connection); for connection group it would be "g".
	identifier := connID + "\x00c\x00" + connID
	enc := base64.RawURLEncoding.EncodeToString([]byte(identifier))
	// Always preserve a trailing "/" before the fragment.
	base := strings.TrimRight(baseURL, "/")
	u, err := url.Parse(base + "/#/client/" + enc)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ErrNoBase indicates the operator hasn't configured a Guacamole base URL.
var ErrNoBase = errors.New("guacamole base URL not configured")
