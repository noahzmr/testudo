package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/engine"
)

// cmdFirewall handles `testudo firewall <status|rules>`: what the running
// daemon's packet filter holds. Rules, NAT and the policy are objects of the
// configuration model and are changed there.
func cmdFirewall(args []string) error {
	const usage = "usage: testudo firewall <status|rules> [--storage DIR]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	storage := fs.String("storage", cfg.StorageDir, "storage directory of the running daemon")
	_ = parseInterleaved(fs, args[1:])
	switch args[0] {
	case "status":
		c, err := dialControl(*storage)
		if err != nil {
			return err
		}
		var v engine.FirewallView
		if err := c.call("GET", "/api/firewall/view", nil, 0, &v); err != nil {
			return err
		}
		switch {
		case !v.HasPolicy:
			fmt.Println("mode:     no firewall policy in the model: nothing is filtered")
		case v.DefaultDeny:
			fmt.Println("mode:     DEFAULT-DENY (enforcing)")
		default:
			fmt.Println("mode:     default-accept (permissive)")
		}
		if v.Policy != "" {
			fmt.Printf("policy:   %s\n", v.Policy)
		}
		fmt.Printf("rules:    %d filter · %d NAT\n", len(v.Rules), len(v.NAT))
		switch {
		case v.Error != "":
			fmt.Printf("kernel:   %s\n", v.Error)
		case v.InSync:
			fmt.Println("kernel:   holds the model's ruleset")
		default:
			fmt.Println("kernel:   differs from the model; the daemon loads it again within 30 s")
		}
		for _, r := range v.Rules {
			state := ""
			if !r.Enabled {
				state = " (disabled)"
			}
			fmt.Printf("  %-24s %-7s %-6s %-40s %10d pkts%s\n", r.Name, r.Direction, strings.ToUpper(r.Action), r.Match, r.Packets, state)
		}
		return nil
	case "rules":
		c, err := dialControl(*storage)
		if err != nil {
			return err
		}
		res, err := c.hc.Get("http://testudo/api/firewall/rendered")
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			b, _ := io.ReadAll(res.Body)
			return fmt.Errorf("%s", strings.TrimSpace(string(b)))
		}
		_, err = io.Copy(os.Stdout, res.Body)
		return err
	case "export":
		return errors.New("`testudo firewall export` was removed: the firewall is part of the configuration model; use `testudo config export`")
	case "apply", "import", "enforce":
		return fmt.Errorf("`testudo firewall %s` was removed: the daemon applies the model and loads it again when the kernel differs", args[0])
	}
	return fmt.Errorf("unknown firewall subcommand: %s\n%s", args[0], usage)
}

// cmdNAT handles `testudo nat list`: the model's NAT rules on this node.
func cmdNAT(args []string) error {
	const usage = "usage: testudo nat list [--storage DIR]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "list":
		cfg := config.Default()
		fs := flag.NewFlagSet("nat", flag.ExitOnError)
		storage := fs.String("storage", cfg.StorageDir, "storage directory of the running daemon")
		_ = parseInterleaved(fs, args[1:])
		c, err := dialControl(*storage)
		if err != nil {
			return err
		}
		var v engine.FirewallView
		if err := c.call("GET", "/api/firewall/view", nil, 0, &v); err != nil {
			return err
		}
		if len(v.NAT) == 0 {
			fmt.Println("no NAT rules on this node")
			return nil
		}
		for _, n := range v.NAT {
			fmt.Printf("  %-24s %-11s %-40s %10d pkts\n", n.Name, n.Direction, n.Match, n.Packets)
		}
		return nil
	case "add", "del":
		return fmt.Errorf("`testudo nat %s` was removed: NAT rules are objects of the configuration model (the console's NAT rules)", args[0])
	}
	return fmt.Errorf("unknown nat subcommand: %s\n%s", args[0], usage)
}
