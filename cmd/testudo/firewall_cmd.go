package main

import (
	"fmt"
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

// cmdFirewall handles `testudo firewall <status|rules|export|apply>`: a view
// of what the manager enforces and a way to put it back into the kernel.
// Changes are made through the configuration model.
func cmdFirewall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: testudo firewall <status|rules|export|apply>")
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

	case "import", "enforce":
		return fmt.Errorf("`testudo firewall %s` was removed: rules, NAT and the default-deny policy are configuration objects now (Web UI, or `testudo config`)", args[0])
	}
	return fmt.Errorf("unknown firewall subcommand: %s", args[0])
}
