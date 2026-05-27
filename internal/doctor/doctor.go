// Package doctor implements `testudo doctor`: a layered, first-failing-layer
// connectivity diagnosis built by composing Testudo's existing probe and
// netlink primitives (internal/probes, internal/netops).
//
// The model mirrors how an operator troubleshoots "no internet": work bottom
// up through the stack - link, address, route, gateway, DNS, WAN, app - and
// the *lowest* layer that fails is the root cause. Everything above a hard
// failure is reported as Skipped rather than producing a cascade of misleading
// secondary errors.
//
// The engine is interface-driven (NetInfo, Prober, Check) so the entire
// diagnosis is unit-testable without touching real sockets or netlink: the
// network-facing dependencies are injected. See system.go for the production
// adapters and NewDefault for the wired-up constructor.
package doctor

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/probes"
)

// Status is the outcome of a single diagnostic check.
type Status string

const (
	StatusPass Status = "pass" // check succeeded
	StatusWarn Status = "warn" // succeeded with a caveat (e.g. captive portal, untestable)
	StatusFail Status = "fail" // check failed - a candidate root cause
	StatusSkip Status = "skip" // prerequisite missing, check not run
)

// Layer orders checks from the link layer outward to the application layer.
// The engine reports the lowest-numbered failing layer as the root cause.
type Layer int

const (
	LayerLink    Layer = iota // physical/L2 link up
	LayerAddress              // host has a routable IP
	LayerRoute                // default route present
	LayerGateway              // gateway reachable
	LayerDNS                  // name resolution works
	LayerWAN                  // a WAN host is reachable by IP
	LayerApp                  // application-layer reachability / captive portal
)

// String returns the short stable name of the layer.
func (l Layer) String() string {
	switch l {
	case LayerLink:
		return "link"
	case LayerAddress:
		return "address"
	case LayerRoute:
		return "route"
	case LayerGateway:
		return "gateway"
	case LayerDNS:
		return "dns"
	case LayerWAN:
		return "wan"
	case LayerApp:
		return "app"
	default:
		return "unknown"
	}
}

// ErrorClass is a machine-readable classification of a check failure, derived
// from the underlying probe error. It lets callers (TUI/web/JSON consumers)
// branch on failure kind without string-matching error text.
type ErrorClass string

const (
	ClassNone       ErrorClass = ""
	ClassTimeout    ErrorClass = "timeout"
	ClassPermission ErrorClass = "permission" // missing CAP_NET_RAW etc - untestable, not necessarily broken
	ClassNoRoute    ErrorClass = "no-route"
	ClassRefused    ErrorClass = "refused"
	ClassDNS        ErrorClass = "dns"
	ClassConfig     ErrorClass = "config" // host-side misconfiguration (no addr, no route, read error)
	ClassUnknown    ErrorClass = "unknown"
)

// Result is the structured outcome of one check.
type Result struct {
	Name    string        `json:"name"`
	Layer   Layer         `json:"layer"`
	LayerID int           `json:"layer_id"`
	Status  Status        `json:"status"`
	Summary string        `json:"summary"`          // one-line human verdict
	Detail  string        `json:"detail,omitempty"` // extra context
	Remedy  string        `json:"remedy,omitempty"` // actionable next step when not pass
	Class   ErrorClass    `json:"class,omitempty"`
	Latency time.Duration `json:"latency_ns"` // time.Duration marshals as nanoseconds
}

// Verdict is the overall health rollup of a diagnosis.
type Verdict string

const (
	VerdictHealthy  Verdict = "healthy"  // every check passed
	VerdictDegraded Verdict = "degraded" // warnings but no hard failure
	VerdictBroken   Verdict = "broken"   // at least one hard failure
)

// Findings is the mutable state shared across checks during a single run.
// Earlier checks populate it; later checks read it to decide whether their
// prerequisite was met (and Skip if not).
type Findings struct {
	UpLinks     []string `json:"up_links"`
	EgressIface string   `json:"egress_iface"`
	GatewayIP   string   `json:"gateway_ip"`
	Resolvers   []string `json:"resolvers"`
}

// Report is the full result of a diagnosis.
type Report struct {
	Results   []Result      `json:"results"`
	RootCause *Result       `json:"root_cause,omitempty"` // copy of the lowest-layer failing check
	Verdict   Verdict       `json:"verdict"`
	Score     int           `json:"score"` // 0-100 composite health
	Findings  Findings      `json:"findings"`
	Started   time.Time     `json:"started"`
	Elapsed   time.Duration `json:"elapsed_ns"` // time.Duration marshals as nanoseconds
}

// NetInfo provides read-only host network state. The production implementation
// wraps a read-only netops.Writer; tests provide a fake.
type NetInfo interface {
	Interfaces() ([]netops.IfaceInfo, error)
	Routes() ([]netops.RouteInfo, error)
	DNSServers() ([]string, error)
}

// Prober runs one-shot reachability probes. The production implementation
// delegates to internal/probes; tests provide a fake.
type Prober interface {
	Run(ctx context.Context, r probes.Request) (*probes.Result, error)
}

// Check is one diagnostic layer. Implementations must respect ctx and must
// never panic - the engine does not recover them (probes already recover
// internally), so a panicking check is a programmer error caught by tests.
type Check interface {
	Name() string
	Layer() Layer
	Run(ctx context.Context, env *Env) Result
}

// Env is the per-run execution context handed to every Check.
type Env struct {
	Net      NetInfo
	Probe    Prober
	HTTP     *http.Client
	Opts     Options
	Findings *Findings
}

// Options tunes a diagnosis. Zero value is not usable - use DefaultOptions.
type Options struct {
	WANTargetIP   string        // ICMP target for raw WAN reachability
	WANTargetName string        // name resolved by the DNS check
	CaptiveURL    string        // expected to return HTTP 204 with empty body
	CheckTimeout  time.Duration // per-check budget
	SkipCaptive   bool          // skip the app-layer captive-portal probe
}

// DefaultOptions returns sensible defaults: Cloudflare for WAN IP/name and the
// gstatic generate_204 endpoint for captive-portal detection.
func DefaultOptions() Options {
	return Options{
		WANTargetIP:   "1.1.1.1",
		WANTargetName: "one.one.one.one",
		CaptiveURL:    "http://connectivitycheck.gstatic.com/generate_204",
		CheckTimeout:  4 * time.Second,
	}
}

// Doctor runs an ordered set of checks against injected dependencies.
type Doctor struct {
	Net    NetInfo
	Probe  Prober
	HTTP   *http.Client
	Opts   Options
	Checks []Check
}

// New builds a Doctor with the default check chain and the supplied
// dependencies. Use NewDefault for production wiring.
func New(net NetInfo, probe Prober, httpc *http.Client, opts Options) *Doctor {
	if httpc == nil {
		httpc = defaultHTTPClient(opts.CheckTimeout)
	}
	return &Doctor{
		Net:   net,
		Probe: probe,
		HTTP:  httpc,
		Opts:  opts,
		Checks: []Check{
			linkCheck{},
			addressCheck{},
			routeCheck{},
			gatewayCheck{},
			dnsCheck{},
			wanCheck{},
			captiveCheck{},
		},
	}
}

// Run executes every check in layer order, sequentially (later checks depend
// on findings from earlier ones), each bounded by Opts.CheckTimeout, and
// returns the assembled report. Run honours ctx cancellation between checks.
func (d *Doctor) Run(ctx context.Context) Report {
	start := time.Now()
	checks := append([]Check(nil), d.Checks...)
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Layer() < checks[j].Layer() })

	env := &Env{Net: d.Net, Probe: d.Probe, HTTP: d.HTTP, Opts: d.Opts, Findings: &Findings{}}
	results := make([]Result, 0, len(checks))

	for _, c := range checks {
		if ctx.Err() != nil {
			break
		}
		cctx := ctx
		var cancel context.CancelFunc
		if d.Opts.CheckTimeout > 0 {
			cctx, cancel = context.WithTimeout(ctx, d.Opts.CheckTimeout)
		}
		cstart := time.Now()
		res := c.Run(cctx, env)
		if cancel != nil {
			cancel()
		}
		if res.Latency == 0 {
			res.Latency = time.Since(cstart)
		}
		res.Name = c.Name()
		res.Layer = c.Layer()
		res.LayerID = int(c.Layer())
		results = append(results, res)
	}

	rep := Report{
		Results:   results,
		RootCause: selectRootCause(results),
		Verdict:   verdict(results),
		Score:     score(results),
		Findings:  *env.Findings,
		Started:   start,
		Elapsed:   time.Since(start),
	}
	return rep
}

// selectRootCause returns a copy of the failing check at the lowest layer, or
// nil if nothing failed. This is the heart of the "first failing layer" model
// and is kept pure for direct testing.
func selectRootCause(results []Result) *Result {
	var best *Result
	for i := range results {
		if results[i].Status != StatusFail {
			continue
		}
		if best == nil || results[i].Layer < best.Layer {
			r := results[i]
			best = &r
		}
	}
	return best
}

// verdict rolls the per-check statuses into one overall grade.
func verdict(results []Result) Verdict {
	worst := VerdictHealthy
	for _, r := range results {
		switch r.Status {
		case StatusFail:
			return VerdictBroken
		case StatusWarn:
			worst = VerdictDegraded
		}
	}
	return worst
}

// score computes a 0-100 composite where lower layers carry more weight: a
// broken link tanks the score far more than a captive-portal warning. Skips
// are neutral so a privilege-limited run isn't penalised for what it couldn't
// test.
func score(results []Result) int {
	s := 100
	for _, r := range results {
		switch r.Status {
		case StatusFail:
			s -= failPenalty(r.Layer)
		case StatusWarn:
			s -= 8
		}
	}
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return s
}

func failPenalty(l Layer) int {
	switch l {
	case LayerLink, LayerAddress, LayerRoute, LayerGateway:
		return 40 // local/core connectivity broken
	case LayerDNS:
		return 30
	case LayerWAN:
		return 25
	default:
		return 10 // app layer
	}
}

func defaultHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		// Do not follow redirects: a 302 to a login page is exactly the
		// captive-portal signal we want to observe.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
