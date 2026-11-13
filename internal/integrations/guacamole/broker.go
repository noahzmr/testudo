package guacamole

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"
)

// Broker turns a PAM grant into a brokered Guacamole session. The resource
// points at a *template* connection (broker ref) that an admin configured in
// Guacamole with the target's credentials; per grant the broker clones its
// parameters into a fresh connection named after the grant, switches session
// recording on, lets the user open it, and returns the connection id. At
// grant end the live session is killed and the connection deleted - the user
// never saw a credential and nothing of theirs remains.
type Broker struct {
	Client *Client
	// RecordingPath / TypescriptPath are directories inside the guacd
	// container/host where session recordings and SSH typescripts land.
	// Empty disables that recording kind.
	RecordingPath  string
	TypescriptPath string
}

// Request is what the PAM layer knows about a grant and its resource.
type Request struct {
	GrantID    string
	User       string // Testudo user; also tried as the Guacamole user name
	Kind       string // ssh | rdp | https (https has no Guacamole protocol)
	Host       string // resource address when no template is given
	Port       uint16
	Login      string // username for the session when no template is given
	TemplateID string // Guacamole connection id to clone (resource broker ref)
}

// Activate creates the per-grant connection and returns its identifier.
func (b *Broker) Activate(ctx context.Context, req Request) (string, error) {
	if b == nil || !b.Client.Configured() {
		return "", ErrNotConfigured
	}
	protocol := ""
	switch req.Kind {
	case "ssh":
		protocol = "ssh"
	case "rdp":
		protocol = "rdp"
	default:
		return "", fmt.Errorf("guacamole: kind %q is not brokered", req.Kind)
	}
	params := map[string]string{}
	if req.TemplateID != "" {
		tp, err := b.Client.ConnectionParameters(ctx, req.TemplateID)
		if err != nil {
			return "", fmt.Errorf("read template connection %s: %w", req.TemplateID, err)
		}
		maps.Copy(params, tp)
		// The protocol follows the template when it has one.
		if _, p, err := b.Client.Connection(ctx, req.TemplateID); err == nil && p != "" {
			protocol = p
		}
	} else {
		params["hostname"] = req.Host
		if req.Port != 0 {
			params["port"] = strconv.Itoa(int(req.Port))
		}
		if req.Login != "" {
			params["username"] = req.Login
		}
	}
	// Recording: one file per grant, named so the grant id is in the path.
	base := "pam-" + req.GrantID + "-${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}"
	if b.RecordingPath != "" {
		params["recording-path"] = b.RecordingPath
		params["recording-name"] = base
		params["create-recording-path"] = "true"
	}
	if b.TypescriptPath != "" && protocol == "ssh" {
		params["typescript-path"] = b.TypescriptPath
		params["typescript-name"] = base
		params["create-typescript-path"] = "true"
	}
	id, err := b.Client.CreateConnection(ctx, ConnectionSpec{
		Name:       "pam-" + req.GrantID + "-" + req.User,
		Protocol:   protocol,
		Parameters: params,
		Attributes: map[string]string{"max-connections": "1", "max-connections-per-user": "1"},
	})
	if err != nil {
		return "", err
	}
	// Best effort: a Guacamole user with the same name may open it. A missing
	// user is not an error - the admin can still hand over the launch URL.
	if err := b.Client.GrantUserRead(ctx, req.User, id); err != nil {
		var apiErr *APIError
		if !asAPIError(err, &apiErr) || apiErr.Status != 404 {
			_ = b.Client.DeleteConnection(ctx, id)
			return "", fmt.Errorf("grant %s access to connection: %w", req.User, err)
		}
	}
	return id, nil
}

// Deactivate kills live sessions of the connection and deletes it.
func (b *Broker) Deactivate(ctx context.Context, connID string) error {
	if b == nil || !b.Client.Configured() || connID == "" {
		return nil
	}
	if _, err := b.Client.KillActiveConnections(ctx, connID); err != nil {
		return err
	}
	return b.Client.DeleteConnection(ctx, connID)
}

// LaunchURL is the deep link that opens the per-grant connection.
func (b *Broker) LaunchURL(connID string) string {
	if b == nil || b.Client == nil || connID == "" {
		return ""
	}
	u, err := BuildURL(b.Client.BaseURL, connID, LaunchSpec{})
	if err != nil {
		return ""
	}
	return u
}

func asAPIError(err error, target **APIError) bool {
	for err != nil {
		if e, ok := err.(*APIError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// String is a safe description for logs (no credentials).
func (r Request) String() string {
	return strings.TrimSpace(fmt.Sprintf("%s %s %s %s:%d", r.GrantID, r.User, r.Kind, r.Host, r.Port))
}
