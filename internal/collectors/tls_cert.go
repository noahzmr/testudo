package collectors

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// TLSCertCollector dials each "host:port" target on a slow cadence (hours,
// not seconds) and checks the leaf certificate's NotAfter. WARN inside
// WarnDays, CRITICAL inside CritDays. Cert expiry is the most common
// preventable outage; once a day is enough to catch it weeks in advance.
type TLSCertCollector struct {
	Targets  []string // "host:port"
	Interval time.Duration
	WarnDays int
	CritDays int
	Timeout  time.Duration
}

func (c *TLSCertCollector) Name() string { return "tls-cert" }

func (c *TLSCertCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Targets) == 0 || c.Interval <= 0 {
		return nil
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.WarnDays <= 0 {
		c.WarnDays = 14
	}
	if c.CritDays <= 0 {
		c.CritDays = 3
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.checkAll(ctx, bus)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.checkAll(ctx, bus)
		}
	}
}

func (c *TLSCertCollector) checkAll(ctx context.Context, bus *events.Bus) {
	var wg sync.WaitGroup
	for _, t := range c.Targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			c.checkOne(ctx, bus, t)
		}(t)
	}
	wg.Wait()
}

func (c *TLSCertCollector) checkOne(ctx context.Context, bus *events.Bus, target string) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// Allow bare hostnames - default to 443.
		host = target
		target = net.JoinHostPort(target, "443")
	}
	dctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: c.Timeout}
	rawConn, err := dialer.DialContext(dctx, "tcp", target)
	if err != nil {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevError),
				Message:  fmt.Sprintf("TLS cert check %s: dial failed: %s", target, err),
			},
		})
		return
	}
	conn := tls.Client(rawConn, &tls.Config{ServerName: host})
	if err := conn.HandshakeContext(dctx); err != nil {
		_ = conn.Close()
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevError),
				Message:  fmt.Sprintf("TLS cert check %s: handshake failed: %s", target, err),
			},
		})
		return
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	if len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	remaining := time.Until(leaf.NotAfter)
	days := int(remaining.Hours() / 24)
	switch {
	case remaining <= 0:
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevCritical),
				Message: fmt.Sprintf("TLS cert for %s EXPIRED %d days ago (CN=%s)",
					target, -days, leaf.Subject.CommonName),
			},
		})
	case days <= c.CritDays:
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevCritical),
				Message: fmt.Sprintf("TLS cert for %s expires in %d days (CN=%s)",
					target, days, leaf.Subject.CommonName),
			},
		})
	case days <= c.WarnDays:
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("TLS cert for %s expires in %d days (CN=%s)",
					target, days, leaf.Subject.CommonName),
			},
		})
	}
}
