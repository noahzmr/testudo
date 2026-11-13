package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/netops"
)

// openDirectFirewall builds a policy manager over an in-process netops writer
// for one-shot CLI use (no engine, no helper). It needs the capabilities the
// live engine's helper normally holds; the usual setcap on the binary covers it.
func openDirectFirewall(allowWrites bool) (*firewall.Manager, error) {
	cfg := config.Default()
	if err := cfg.EnsureDirs(); err != nil {
		return nil, err
	}
	nw := &netops.Writer{AllowWrites: allowWrites}
	return firewall.Open(firewall.Options{
		Path:              firewallPolicyPathFor(cfg),
		ProtectedTCPPorts: protectedPortsFor(cfg),
	}, nw)
}

func firewallPolicyPathFor(cfg config.Config) string {
	return cfg.StorageDir + string(os.PathSeparator) + "firewall.json"
}

// protectedPortsFor mirrors the engine's anti-lockout set: SSH plus the Web
// UI port from the default listen address.
func protectedPortsFor(cfg config.Config) []uint16 {
	ports := []uint16{22}
	if i := strings.LastIndex(cfg.WebListen, ":"); i >= 0 {
		if p, err := parsePort(cfg.WebListen[i+1:]); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}

// cmdFirewall handles `testudo firewall <status|rules|export|import|apply|enforce>`.
func cmdFirewall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: testudo firewall <status|rules|export|import|apply|enforce> ...")
	}
	switch args[0] {
	case "status":
		m, err := openDirectFirewall(false)
		if err != nil {
			return err
		}
		d := m.Reconcile() // read-only with writes disabled: reports drift
		st := m.Status()
		mode := "default-accept (permissive)"
		if st.Enforce {
			mode = "DEFAULT-DENY (enforcing)"
		}
		fmt.Printf("policy:   %s\n", st.Path)
		fmt.Printf("mode:     %s\n", mode)
		fmt.Printf("rules:    %d filter · %d forwards · %d masquerades\n", st.RuleCount, st.ForwardCount, st.MasqCount)
		if d.Error != "" {
			fmt.Printf("kernel:   unreadable (%s)\n", d.Error)
		} else if st.Inert && !d.TableExists {
			fmt.Println("kernel:   nothing installed (policy is inert: no rules, default-accept)")
		} else if d.InSync {
			fmt.Println("kernel:   in sync")
		} else {
			fmt.Printf("kernel:   DRIFT - %s\n", strings.Join(d.Details, "; "))
			fmt.Println("          run `testudo firewall apply` (needs CAP_NET_ADMIN) or let the live engine reconcile")
		}
		if !st.UpdatedAt.IsZero() {
			fmt.Printf("updated:  %s\n", st.UpdatedAt.Format(time.RFC3339))
		}
		return nil

	case "rules":
		m, err := openDirectFirewall(false)
		if err != nil {
			return err
		}
		fmt.Print(m.RenderNFT())
		return nil

	case "export":
		m, err := openDirectFirewall(false)
		if err != nil {
			return err
		}
		data, err := m.Export()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(data, '\n'))
		return err

	case "import":
		fs := flag.NewFlagSet("firewall import", flag.ExitOnError)
		file := fs.String("file", "-", "policy JSON to import ('-' = stdin)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var data []byte
		var err error
		if *file == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*file)
		}
		if err != nil {
			return err
		}
		m, err := openDirectFirewall(true)
		if err != nil {
			return err
		}
		if err := m.Import(data); err != nil {
			return err
		}
		fmt.Println("policy imported and applied")
		return nil

	case "apply":
		m, err := openDirectFirewall(true)
		if err != nil {
			return err
		}
		if err := m.Apply(); err != nil {
			return err
		}
		fmt.Println("policy applied")
		return nil

	case "enforce":
		fs := flag.NewFlagSet("firewall enforce", flag.ExitOnError)
		confirmSec := fs.Int("confirm-sec", 60, "auto-revert window in seconds when enabling (0 = no safety net)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		rest := fs.Args()
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
			return fmt.Errorf("usage: testudo firewall enforce <on|off> [--confirm-sec N]")
		}
		m, err := openDirectFirewall(true)
		if err != nil {
			return err
		}
		if rest[0] == "off" {
			if err := m.SetEnforce(false, 0); err != nil {
				return err
			}
			fmt.Println("default-deny disabled")
			return nil
		}
		window := time.Duration(*confirmSec) * time.Second
		if err := m.SetEnforce(true, window); err != nil {
			return err
		}
		if window == 0 {
			fmt.Println("default-deny enabled")
			return nil
		}
		// Commit-confirm from a terminal: the operator proves they are still
		// connected by answering; silence (a cut session) reverts.
		fmt.Printf("default-deny enabled - still connected? type 'yes' within %ds to keep it: ", *confirmSec)
		answer := make(chan string, 1)
		go func() {
			var s string
			_, _ = fmt.Fscanln(os.Stdin, &s)
			answer <- strings.TrimSpace(strings.ToLower(s))
		}()
		select {
		case s := <-answer:
			if s == "yes" || s == "y" {
				if err := m.ConfirmEnforce(); err != nil {
					return err
				}
				fmt.Println("confirmed")
				return nil
			}
			_ = m.SetEnforce(false, 0)
			fmt.Println("not confirmed - reverted to default-accept")
			return nil
		case <-time.After(window + 2*time.Second):
			fmt.Println("no answer - reverted to default-accept")
			return nil
		}
	}
	return fmt.Errorf("unknown firewall subcommand: %s", args[0])
}
