package doctor

import (
	"context"
	"net/http"

	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/probes"
)

// netopsInfo is the production NetInfo, backed by a read-only netops.Writer.
// Writes are never enabled here: doctor only inspects, never mutates.
type netopsInfo struct{ w *netops.Writer }

func (n netopsInfo) Interfaces() ([]netops.IfaceInfo, error) { return n.w.ListIfaces() }
func (n netopsInfo) Routes() ([]netops.RouteInfo, error)     { return n.w.ListRoutes() }
func (n netopsInfo) DNSServers() ([]string, error)           { return n.w.ListDNSServers() }

// RealNetInfo returns a NetInfo backed by live netlink/proc reads.
func RealNetInfo() NetInfo { return netopsInfo{w: &netops.Writer{AllowWrites: false}} }

// probesRunner is the production Prober, delegating to internal/probes. The
// probes package already recovers panics internally and returns them as a
// Result with Err set, so this adapter cannot panic the engine.
type probesRunner struct{}

func (probesRunner) Run(ctx context.Context, r probes.Request) (*probes.Result, error) {
	return probes.Run(ctx, r)
}

// RealProber returns a Prober backed by internal/probes.
func RealProber() Prober { return probesRunner{} }

// NewDefault wires a Doctor with live network dependencies. This is the
// constructor the CLI/TUI/web should call.
func NewDefault(opts Options) *Doctor {
	return New(RealNetInfo(), RealProber(), defaultHTTPClient(opts.CheckTimeout), opts)
}

// newGetRequest builds a context-bound GET. Isolated so the captive-portal
// check stays free of net/http import noise and is easy to read.
func newGetRequest(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}
