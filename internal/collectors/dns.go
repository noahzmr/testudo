package collectors

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// DNSCollector resolves a fixed list of names at a fixed interval using the
// host's stub resolver and reports per-query latency + outcome.
type DNSCollector struct {
	Names    []string
	Interval time.Duration
	Timeout  time.Duration

	resolver *net.Resolver
}

func (c *DNSCollector) Name() string { return "dns" }

func (c *DNSCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Names) == 0 {
		return nil
	}
	c.resolver = &net.Resolver{PreferGo: false}

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

func (c *DNSCollector) probeAll(ctx context.Context, bus *events.Bus) {
	var wg sync.WaitGroup
	for _, name := range c.Names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			qctx, cancel := context.WithTimeout(ctx, c.Timeout)
			defer cancel()
			start := time.Now()
			addrs, err := c.resolver.LookupHost(qctx, name)
			dur := time.Since(start)
			if err != nil {
				bus.Publish(events.Event{
					Kind: events.KindDNSFailure, Source: c.Name(),
					Payload: events.DNSFailurePayload{
						Name: name, Duration: dur, Err: err.Error(),
					},
				})
				return
			}
			payload := events.DNSResultPayload{
				Name: name, Duration: dur, Answers: len(addrs),
				IPs: append([]string{}, addrs...),
			}
			bus.Publish(events.Event{
				Kind: events.KindDNSResult, Source: c.Name(),
				Payload: payload,
			})
		}(name)
	}
	wg.Wait()
}
