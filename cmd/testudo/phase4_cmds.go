package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/engine"
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
	"github.com/noahzmr/testudo/internal/probes"
	"github.com/noahzmr/testudo/internal/web"
)

// promptPassword reads a password line from stdin after a prompt on
// stderr; pipe it in for scripts.
func promptPassword(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", fmt.Errorf("empty password")
	}
	return pw, nil
}

// cmdWeb runs the live engine + the embedded HTTP UI (no TUI).
func cmdWeb(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fs.String("listen", cfg.WebListen, "HTTP bind address (host:port)")
	dbPath := fs.String("db", cfg.SQLitePath, "SQLite database path")
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	allowWrites := fs.Bool("allow-netops-write", false, "permit netlink/nftables/netplan writes (firewall, routes, NAT, WireGuard management)")
	usePrivsep := fs.Bool("privsep", true, "run privileged netops in a separate helper process and drop the engine's capabilities (set false for legacy single-process mode)")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with this certificate chain (PEM); requires --tls-key")
	tlsKey := fs.String("tls-key", "", "private key (PEM) for --tls-cert")
	clusterRaft := fs.String("cluster-raft", "", "listen address of the cluster's consensus transport (host:port on the site mesh); empty: this node never joins a cluster")
	clusterAPI := fs.String("cluster-api", "", "listen address of the cluster's member API (host:port on the site mesh)")
	clusterAdvRaft := fs.String("cluster-advertise-raft", "", "address other members reach the consensus transport at (default: --cluster-raft)")
	clusterAdvAPI := fs.String("cluster-advertise-api", "", "address other members reach the member API at (default: --cluster-api)")
	nodeName := fs.String("node-name", "", "this member's name in the cluster (default: the host name)")
	publicURL := fs.String("public-url", "", "address people reach this console at (https://fw.example.com); used to send visitors of published services here to log in")
	tlsAuto := fs.Bool("tls-auto", false, "serve HTTPS with a self-signed certificate generated into <storage>/tls on first use")
	logJSON := fs.Bool("log-json", false, "write the log as JSON lines on stderr, for journald or a log shipper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logJSON {
		// The log package's output goes through this handler from now on.
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must be given together")
	}
	cfg.WebListen = *listen
	if (*clusterRaft == "") != (*clusterAPI == "") {
		return fmt.Errorf("--cluster-raft and --cluster-api must be given together")
	}
	cfg.ClusterRaft, cfg.ClusterAPI, cfg.NodeName = *clusterRaft, *clusterAPI, *nodeName
	cfg.ClusterAdvertiseRaft, cfg.ClusterAdvertiseAPI = *clusterAdvRaft, *clusterAdvAPI
	cfg.SQLitePath = *dbPath
	cfg.StorageDir = *storageDir
	cfg.SettingsPath = filepath.Join(*storageDir, "settings.json")
	cfg.WebEnabled = true
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}

	store, err := openStore(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer store.Close()

	settings := config.NewSettingsStore(cfg.SettingsPath)
	_ = settings.Load()
	// --allow-netops-write=true wins; otherwise the persisted setting stands.
	if *allowWrites {
		_ = settings.Update(func(t *config.Thresholds) { t.AllowNetopsWrite = true })
	}
	cfg.Thresholds = settings.Snapshot()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Privilege separation: spawn the helper (if enabled) and drop the engine's
	// capabilities before starting, so the web server runs unprivileged and
	// privileged netops/WireGuard/netplan writes go through the audited helper.
	nw, helperClient, helperState := setupNetops(ctx, cfg, cfg.Thresholds.AllowNetopsWrite, *usePrivsep)
	dsn := cfg.Thresholds.SentryDSN
	if dsn == "" {
		dsn = cfg.SentryDSN
	}
	_ = sentryx.Init(dsn, "testudo")
	defer sentryx.Flush()

	eng := engine.New(cfg, store, settings, nw)
	if helperClient != nil {
		eng.SetCaptureSpawner(helperCaptureSpawner{client: helperClient})
	}
	if err := eng.Start(ctx); err != nil {
		return err
	}
	helperState.report(eng)
	if pw := eng.FirstRunPassword(); pw != "" {
		fmt.Fprintf(os.Stderr, "⚠ first run - created default user 'testudo' with password: %s\n", pw)
		fmt.Fprintln(os.Stderr, "  change it in the console (your user menu) or with: testudo user passwd testudo")
	}
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = eng.Stop(shutdownCtx)
	}()

	srv := web.New(eng, cfg.WebListen)
	srv.PublicURL = *publicURL
	srv.ControlSocket = controlSocketPath(cfg.StorageDir)
	srv.TLS = web.TLSConfig{
		CertFile: *tlsCert, KeyFile: *tlsKey, Auto: *tlsAuto,
		Dir:   filepath.Join(cfg.StorageDir, "tls"),
		Hosts: []string{strings.Split(cfg.WebListen, ":")[0]},
	}
	scheme := "http"
	if srv.TLS.Enabled() {
		scheme = "https"
	} else {
		fmt.Fprintln(os.Stderr, "⚠ serving plain HTTP - use --tls-auto or --tls-cert/--tls-key before exposing this beyond a trusted LAN")
	}
	fmt.Fprintf(os.Stderr, "Testudo web UI listening on %s://%s\n", scheme, cfg.WebListen)
	return srv.ListenAndServe(ctx)
}

// cmdDiscover runs one round of network discovery from the CLI and prints
// the inventory. Useful for scripts and quick ad-hoc scans. With --active
// also fires ARP broadcast, ICMP sweep, mDNS query and SNMPv2c GET; with
// --lldp also listens for LLDP frames for the duration of --wait.
func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	active := fs.Bool("active", false, "run active probes (ARP sweep, ICMP, mDNS, SNMP) - needs CAP_NET_RAW")
	lldp := fs.Bool("lldp", true, "listen for LLDP frames from directly-connected neighbours")
	community := fs.String("snmp-community", "public", "SNMPv2c read community (empty disables SNMP)")
	wait := fs.Duration("wait", 6*time.Second, "wait for scans / LLDP listening to complete")
	maxBits := fs.Int("max-subnet-bits", 10, "cap subnet expansion for active sweeps (10 = /22)")
	intensity := fs.String("intensity", "balanced", "scan intensity: fast, balanced, or aggressive")
	verbose := fs.Bool("v", false, "print SNMP/LLDP details when available")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inv := discovery.NewInventory()
	scanner := &discovery.Scanner{
		Inventory:     inv,
		Active:        *active,
		Interval:      24 * time.Hour,
		MaxSubnetBits: *maxBits,
		SNMPCommunity: *community,
		SNMPTimeout:   time.Second,
		Intensity:     *intensity,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = scanner.Run(ctx, nil)
		close(done)
	}()
	if *lldp {
		l := &discovery.LLDPListener{Inventory: inv}
		go func() { _ = l.Run(ctx) }()
	}
	<-ctx.Done()
	<-done

	devs := inv.Snapshot()
	if len(devs) == 0 {
		fmt.Println("no devices discovered")
		return nil
	}
	fmt.Printf("%-16s %-19s %-22s %-10s %-16s %s\n",
		"IP", "MAC", "HOSTNAME", "TYPE", "VENDOR", "SOURCE")
	for _, d := range devs {
		fmt.Printf("%-16s %-19s %-22s %-10s %-16s %s\n",
			d.IP, dashIfEmpty(d.MAC), dashIfEmpty(d.Hostname),
			dashIfEmpty(d.DeviceType), dashIfEmpty(d.Vendor), d.Source)
		if !*verbose {
			continue
		}
		if d.SysDescr != "" {
			fmt.Printf("    sysDescr: %s\n", d.SysDescr)
		}
		if d.SysName != "" && d.SysName != d.Hostname {
			fmt.Printf("    sysName:  %s\n", d.SysName)
		}
		if d.SysLocation != "" {
			fmt.Printf("    location: %s\n", d.SysLocation)
		}
		if d.SysUptime != "" {
			fmt.Printf("    uptime:   %s\n", d.SysUptime)
		}
		if d.LLDPChassisID != "" {
			fmt.Printf("    LLDP:     chassis=%s port=%s caps=%s\n",
				d.LLDPChassisID, d.LLDPPortID, strings.Join(d.LLDPCapabilities, ","))
		}
	}
	return nil
}

// cmdProbe runs a single diagnostic probe from the CLI.
func cmdProbe(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: testudo probe <icmp|tcp|udp|dns|throughput|traceroute> <target> [port]")
	}
	kind := probes.Kind(args[0])
	target := args[1]
	var port uint16
	if len(args) >= 3 {
		p, err := parsePort(args[2])
		if err != nil {
			return err
		}
		port = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := probes.Run(ctx, probes.Request{
		Kind: kind, Target: target, Port: port, Timeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.OK {
		fmt.Printf("OK  %-12s latency=%s  %s\n", kind, res.Latency, res.Detail)
		if len(res.Hops) > 0 {
			for _, h := range res.Hops {
				fmt.Printf("  TTL=%-3d %-16s %s\n", h.TTL, h.IP, h.Latency)
			}
		}
		if res.Mbps > 0 {
			fmt.Printf("  throughput: %.1f Mbps\n", res.Mbps)
		}
	} else {
		fmt.Printf("FAIL %-12s %s\n", kind, firstNonEmpty(res.Detail, res.Err))
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var _ = strings.Join // keep strings imported in case future cmds need it
