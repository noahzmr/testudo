// Testudo - terminal-native network quality observatory.
//
// Subcommands:
//
//	testudo            (default: live capture + TUI)
//	testudo live       same as default
//	testudo sessions   interactive session browser
//	testudo replay ID  open a past session in the replay TUI
//	testudo ifaces     list capturable interfaces (for --iface)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/engine"
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/tui"
)

const banner = `      ___    __________ ________   ______ __________  __   __   _______     ______
 ,,  // \\   \__    __/ |  ____/  /  ___/ \__    __/ |  | |  | |   ___  \  /  __   \
(_,\/ \_/ \     |  |    |  |___   \  \       |  |    |  | |  | |  |   \  \ |  |  |  |
  \ \_/_\_/>    |  |    |   ___|   \  \      |  |    |  | |  | |  |   |  | |  |  |  |
  /_/  /_/      |  |    |  |_____  /  /      |  |    |  |_|  | |  |___/  / |  |__|  |
                |__|    |_______/ /__/       |__|     \_____/  |________/   \______/`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "testudo:", err)
		os.Exit(1)
	}
}

func run() error {
	cmd := "live"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "live":
		return cmdLive(args)
	case "sessions":
		return cmdSessions(args)
	case "replay":
		return cmdReplay(args)
	case "ifaces":
		return cmdIfaces()
	case "nat":
		return cmdNAT(args)
	case "routes":
		return cmdRoutes(args)
	case "user":
		return cmdUser(args)
	case "web":
		return cmdWeb(args)
	case "discover":
		return cmdDiscover(args)
	case "probe":
		return cmdProbe(args)
	case "doctor":
		return cmdDoctor(args)
	case "version":
		fmt.Println("testudo (phase 4)")
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func usage() {
	fmt.Println(banner)
	fmt.Println()
	fmt.Println("Usage: testudo [command] [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  live              start live capture + TUI (default)")
	fmt.Println("  web               start the HTTP UI (no TUI) - see flags with `web --help`")
	fmt.Println("  sessions          interactive session browser")
	fmt.Println("  replay <id>       open a past session in the replay TUI")
	fmt.Println("  ifaces            list capturable interfaces")
	fmt.Println("  routes            show kernel routing table")
	fmt.Println("  nat list          show Testudo-managed port forwards")
	fmt.Println("  nat add <proto> <wan> <lan-ip>[:<lan-port>]   add port forward")
	fmt.Println("  nat del <proto> <wan>                          remove port forward")
	fmt.Println("  discover [--active] [--lldp] [--snmp-community] one-shot scan (ARP/ICMP/mDNS/LLDP/SNMP)")
	fmt.Println("  probe <kind> <target> [port]                   one-shot probe (icmp/tcp/udp/dns/throughput/traceroute)")
	fmt.Println("  doctor [--target-ip] [--json] [--no-captive]   layered connectivity diagnosis (first failing layer = root cause)")
	fmt.Println("  user passwd [name]                             set/rotate user password (web UI auth)")
	fmt.Println("  user list                                      list configured users")
	fmt.Println("  version           print version")
	fmt.Println("  help              show this message")
	fmt.Println()
	fmt.Println("Flow capture requires CAP_NET_RAW. Grant it once with:")
	fmt.Println("  sudo setcap cap_net_raw,cap_net_admin=+ep ./testudo")
	fmt.Println()
	fmt.Println("Network management writes (route add/del, iface up/down, NAT add/del)")
	fmt.Println("are disabled by default. Enable with:")
	fmt.Println("  ./testudo live --allow-netops-write")
}

func cmdLive(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	targets := fs.String("targets", strings.Join(cfg.ICMPTargets, ","), "comma-separated ICMP targets")
	dns := fs.String("dns", strings.Join(cfg.DNSNames, ","), "comma-separated DNS names to probe")
	interval := fs.Duration("interval", cfg.ICMPInterval, "ICMP probe interval")
	dnsInterval := fs.Duration("dns-interval", cfg.DNSInterval, "DNS probe interval")
	dbPath := fs.String("db", cfg.SQLitePath, "SQLite database path")
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	enableCapture := fs.Bool("capture", false, "enable packet capture (needs CAP_NET_RAW)")
	iface := fs.String("iface", "", "comma-separated interfaces to capture on; empty = auto-discover all")
	allowWrites := fs.Bool("allow-netops-write", false, "permit netlink writes (iface up/down, route add/del, NAT add/del)")
	bufferbloat := fs.Bool("bufferbloat", false, "enable bufferbloat probe (saturates link periodically to measure loaded-RTT delta)")
	bufferbloatTarget := fs.String("bufferbloat-target", cfg.BufferbloatTarget, "ping target during bufferbloat probe")
	bufferbloatEvery := fs.Duration("bufferbloat-interval", cfg.BufferbloatInterval, "gap between bufferbloat runs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg.ICMPTargets = splitCSV(*targets)
	cfg.DNSNames = splitCSV(*dns)
	cfg.ICMPInterval = *interval
	cfg.DNSInterval = *dnsInterval
	cfg.StorageDir = *storageDir
	cfg.SQLitePath = *dbPath
	cfg.CaptureEnabled = *enableCapture || *iface != ""
	if *iface != "" {
		cfg.CaptureIfaces = splitCSV(*iface)
	}
	cfg.BufferbloatEnabled = *bufferbloat
	if *bufferbloatTarget != "" {
		cfg.BufferbloatTarget = *bufferbloatTarget
	}
	if *bufferbloatEvery > 0 {
		cfg.BufferbloatInterval = *bufferbloatEvery
	}

	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	store, err := storage.Open(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer store.Close()

	settings := config.NewSettingsStore(cfg.SettingsPath)
	_ = settings.Load()
	// CLI flag overrides whatever is persisted, but only when explicitly set.
	// We can't easily detect "flag was passed" without flag.Visit, so the
	// rule is: --allow-netops-write=true wins; otherwise persisted state wins.
	if *allowWrites {
		_ = settings.Update(func(t *config.Thresholds) { t.AllowNetopsWrite = true })
	}
	cfg.Thresholds = settings.Snapshot()
	nw := &netops.Writer{AllowWrites: cfg.Thresholds.AllowNetopsWrite}

	// Hook Sentry from persisted Settings (CLAUDE.md: "The Sentry DSN is
	// configured in Settings"). Empty DSN is a no-op; the Settings tab can
	// rotate the DSN at runtime via afterApplyString.
	_ = sentryx.Init(cfg.Thresholds.SentryDSN, "testudo")
	defer sentryx.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eng := engine.New(cfg, store, settings, nw)
	if err := eng.Start(ctx); err != nil {
		return err
	}

	runErr := tui.Run(ctx, tui.NewApp(eng))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = eng.Stop(shutdownCtx)
	return runErr
}

func cmdSessions(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	dbPath := fs.String("db", cfg.SQLitePath, "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.SQLitePath = *dbPath
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	picked, err := tui.RunBrowser(ctx, tui.NewBrowser(store))
	if err != nil {
		return err
	}
	if picked == "" {
		return nil
	}
	// User chose a session - chain into the replay TUI.
	return tui.RunReplay(ctx, tui.NewReplay(store, picked))
}

func cmdReplay(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	dbPath := fs.String("db", cfg.SQLitePath, "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("replay requires a session ID - run `testudo sessions` to browse them")
	}
	sessionID := fs.Arg(0)
	cfg.SQLitePath = *dbPath
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return tui.RunReplay(ctx, tui.NewReplay(store, sessionID))
}

func cmdIfaces() error {
	ifs, err := capture.ListInterfaces()
	if err != nil {
		return err
	}
	if len(ifs) == 0 {
		fmt.Println("no capturable interfaces found")
		return nil
	}
	fmt.Println("Capturable interfaces:")
	for _, name := range ifs {
		fmt.Println("  " + name)
	}
	return nil
}

func cmdNAT(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: testudo nat <list|add|del> ...")
	}
	nw := &netops.Writer{AllowWrites: true}
	switch args[0] {
	case "list":
		fws, err := nw.ListPortForwards()
		if err != nil {
			return err
		}
		if len(fws) == 0 {
			fmt.Println("no Testudo-managed port forwards")
			return nil
		}
		for _, pf := range fws {
			fmt.Printf("  %s wan=%d -> %s:%d\n", strings.ToUpper(pf.Proto), pf.WANPort, pf.LANIP, pf.LANPort)
		}
		return nil
	case "add":
		if len(args) < 4 {
			return fmt.Errorf("usage: testudo nat add <tcp|udp> <wan-port> <lan-ip>[:<lan-port>]")
		}
		proto := args[1]
		wan, err := parsePort(args[2])
		if err != nil {
			return fmt.Errorf("wan port: %w", err)
		}
		lanIP, lanPort, err := parseHostPort(args[3], wan)
		if err != nil {
			return fmt.Errorf("lan target: %w", err)
		}
		return nw.AddPortForward(netops.PortForward{
			Proto: proto, WANPort: wan, LANIP: lanIP, LANPort: lanPort,
		})
	case "del":
		if len(args) < 3 {
			return fmt.Errorf("usage: testudo nat del <tcp|udp> <wan-port>")
		}
		proto := args[1]
		wan, err := parsePort(args[2])
		if err != nil {
			return fmt.Errorf("wan port: %w", err)
		}
		return nw.DelPortForward(proto, wan)
	}
	return fmt.Errorf("unknown nat subcommand: %s", args[0])
}

func cmdRoutes(args []string) error {
	_ = args
	nw := &netops.Writer{AllowWrites: false}
	routes, err := nw.ListRoutes()
	if err != nil {
		return err
	}
	for _, r := range routes {
		gw := r.Gateway
		if gw == "" {
			gw = "-"
		}
		iface := r.Iface
		if iface == "" {
			iface = "-"
		}
		fmt.Printf("  %-6s %-20s via %-15s dev %s metric %d %s\n",
			r.Family, r.Dst, gw, iface, r.Metric, r.Scope)
	}
	return nil
}

func parsePort(s string) (uint16, error) {
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, err
	}
	if v < 1 || v > 65535 {
		return 0, fmt.Errorf("port out of range: %d", v)
	}
	return uint16(v), nil
}

func parseHostPort(s string, defaultPort uint16) (string, uint16, error) {
	if idx := strings.LastIndex(s, ":"); idx > 0 && idx < len(s)-1 {
		host := s[:idx]
		p, err := parsePort(s[idx+1:])
		if err != nil {
			return "", 0, err
		}
		return host, p, nil
	}
	return s, defaultPort, nil
}

// openStore is a tiny indirection so phase4_cmds.go can share the same
// storage-open path as cmdLive without re-importing the storage package
// only to forward one call.
func openStore(path string) (*storage.Store, error) {
	return storage.Open(path)
}

// newEngineWithSettings builds an engine using the given settings store,
// with netops writes disabled (cmdWeb runs read-only by default; the user
// can still mutate state through the live mode).
func newEngineWithSettings(cfg config.Config, store *storage.Store, settings *config.SettingsStore) *engine.Engine {
	nw := &netops.Writer{AllowWrites: false}
	// Hook Sentry from persisted Settings, falling back to the static cfg
	// field for back-compat with environments that still wire the DSN there.
	dsn := settings.Snapshot().SentryDSN
	if dsn == "" {
		dsn = cfg.SentryDSN
	}
	_ = sentryx.Init(dsn, "testudo")
	return engine.New(cfg, store, settings, nw)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
