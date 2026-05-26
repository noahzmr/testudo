package collectors

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// HTTPEndpointCollector GETs each endpoint at Interval and reports
// time-to-first-byte plus the status-code class. TCP-connect alone tells
// you the port is open; an HTTP probe tells you the application behind
// the port is actually responding. TLS handshake duration is captured
// via net/http/httptrace so encrypted-endpoint slowness is visible
// distinct from server slowness.
type HTTPEndpointCollector struct {
	Endpoints []string
	Interval  time.Duration
	Timeout   time.Duration
}

func (c *HTTPEndpointCollector) Name() string { return "http" }

func (c *HTTPEndpointCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Endpoints) == 0 || c.Interval <= 0 {
		return nil
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.probeAll(ctx, bus)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.probeAll(ctx, bus)
		}
	}
}

func (c *HTTPEndpointCollector) probeAll(ctx context.Context, bus *events.Bus) {
	var wg sync.WaitGroup
	for _, url := range c.Endpoints {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			c.probeOne(ctx, bus, url)
		}(url)
	}
	wg.Wait()
}

func (c *HTTPEndpointCollector) probeOne(ctx context.Context, bus *events.Bus, url string) {
	qctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	var (
		connectStart time.Time
		tlsStart     time.Time
		connectDur   time.Duration
		tlsDur       time.Duration
		ttfb         time.Duration
		start        = time.Now()
	)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				connectDur = time.Since(connectStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsDur = time.Since(tlsStart)
			}
		},
		GotFirstResponseByte: func() { ttfb = time.Since(start) },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(qctx, trace),
		http.MethodGet, url, nil)
	if err != nil {
		c.fail(bus, url, time.Since(start), err.Error())
		return
	}
	client := &http.Client{
		Timeout: c.Timeout,
		// Don't follow redirects - each endpoint should be probed as
		// configured. A 301 is still a successful response.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		c.fail(bus, url, time.Since(start), err.Error())
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	bus.Publish(events.Event{
		Kind: events.KindLatency, Source: c.Name(),
		Payload: events.LatencyPayload{Target: url, RTT: ttfb},
	})

	// Anomaly classification by status class:
	//   2xx/3xx => silent (success)
	//   4xx     => INFO (probably a config issue, not an outage)
	//   5xx     => ERROR (service is up but broken)
	switch {
	case resp.StatusCode >= 500:
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevError),
				Message:  fmt.Sprintf("HTTP %d from %s (ttfb=%s, tls=%s, connect=%s)", resp.StatusCode, url, ttfb, tlsDur, connectDur),
			},
		})
	case resp.StatusCode >= 400:
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevInfo),
				Message:  fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url),
			},
		})
	}
}

func (c *HTTPEndpointCollector) fail(bus *events.Bus, url string, dur time.Duration, msg string) {
	bus.Publish(events.Event{
		Kind: events.KindPacketLoss, Source: c.Name(),
		Payload: events.PacketLossPayload{Target: url, Sent: 1, Lost: 1, LossPct: 100},
	})
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(events.SevError),
			Message:  fmt.Sprintf("HTTP probe %s failed after %s: %s", url, dur, msg),
		},
	})
}
