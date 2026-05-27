package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/probes"
	"github.com/noahzmr/testudo/internal/web"
)

// cmdUser handles `testudo user passwd` and `testudo user list`.
// Password input is read from a terminal prompt (no echo support yet -
// echo-suppress on TTYs requires golang.org/x/term, which we'd rather not
// pull in for a one-shot. The user can pipe via stdin.)
func cmdUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: testudo user <passwd|list>")
	}
	cfg := config.Default()
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	usersPath := filepath.Join(cfg.StorageDir, "users.json")
	store, err := auth.Open(usersPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		names := store.ListNames()
		if len(names) == 0 {
			fmt.Println("no users configured")
			return nil
		}
		for _, n := range names {
			fmt.Println("  " + n)
		}
		return nil
	case "passwd":
		name := "testudo"
		if len(args) >= 2 {
			name = args[1]
		}
		fmt.Fprintf(os.Stderr, "New password for %s: ", name)
		var pw string
		if _, err := fmt.Fscanln(os.Stdin, &pw); err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if err := store.SetPassword(name, pw); err != nil {
			return err
		}
		fmt.Printf("password updated for user %q\n", name)
		return nil
	}
	return fmt.Errorf("unknown user subcommand: %s", args[0])
}

// cmdWeb runs the live engine + the embedded HTTP UI (no TUI).
func cmdWeb(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fs.String("listen", cfg.WebListen, "HTTP bind address (host:port)")
	dbPath := fs.String("db", cfg.SQLitePath, "SQLite database path")
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.WebListen = *listen
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

	users, err := auth.Open(filepath.Join(cfg.StorageDir, "users.json"))
	if err != nil {
		return err
	}
	if pw, err := users.Bootstrap("testudo"); err != nil {
		return err
	} else if pw != "" {
		fmt.Fprintf(os.Stderr, "⚠ first run - created default user 'testudo' with password: %s\n", pw)
		fmt.Fprintln(os.Stderr, "  rotate with: testudo user passwd")
	}

	settings := config.NewSettingsStore(cfg.SettingsPath)
	_ = settings.Load()
	cfg.Thresholds = settings.Snapshot()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eng := newEngineWithSettings(cfg, store, settings)
	if err := eng.Start(ctx); err != nil {
		return err
	}
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = eng.Stop(shutdownCtx)
	}()

	srv := web.New(eng, users, cfg.WebListen)
	fmt.Fprintf(os.Stderr, "Testudo web UI listening on http://%s\n", cfg.WebListen)
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
