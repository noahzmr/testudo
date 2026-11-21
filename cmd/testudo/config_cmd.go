package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confimport"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
)

// cmdConfig handles `testudo config <status|history|export|import-legacy|compact>`.
// Commands that write need the daemon to be stopped: the store has one writer.
func cmdConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: testudo config <status|history|export|import-legacy|compact> ...")
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("config "+args[0], flag.ExitOnError)
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	apply := fs.Bool("apply", false, "import-legacy: write the result into the model (default: only show it)")
	limit := fs.Int("n", 20, "history: number of records")
	keep := fs.Int("keep", 1000, "compact: number of recent records to keep in the log")
	_ = fs.Parse(args[1:])
	cfg.StorageDir = *storageDir
	dir := engine.ConfigDir(cfg)

	openForWrite := func() (*confstore.Store, error) {
		s, err := confstore.Open(dir)
		if errors.Is(err, confstore.ErrLocked) {
			return nil, fmt.Errorf("the daemon is running and owns the configuration store; stop it first or use the web API")
		}
		return s, err
	}

	switch args[0] {
	case "status":
		st, err := confstore.ReadState(dir)
		if err != nil {
			return err
		}
		fmt.Printf("store:    %s\nrecord:   %d\nschema:   %d\n", dir, st.Index(), model.SchemaVersion)
		for _, info := range model.Kinds() {
			if n := len(st.List(info.Kind)); n > 0 {
				fmt.Printf("  %-18s %d\n", info.Kind, n)
			}
		}
		if n := len(st.ChangeSets()); n > 0 {
			fmt.Printf("change sets waiting: %d\n", n)
		}
		if _, err := os.Stat(filepath.Join(dir, "pending-apply.json")); err == nil {
			fmt.Println("a change is waiting for confirmation")
		}
		return nil

	case "export":
		st, err := confstore.ReadState(dir)
		if err != nil {
			return err
		}
		snap := st.Export()
		snap.ChangeSets = nil
		fmt.Fprintln(os.Stderr, "note: the export contains secrets; store it with mode 0600")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)

	case "history":
		s, err := openForWrite()
		if err != nil {
			return err
		}
		defer s.Close()
		recs, err := s.History(0, *limit)
		if err != nil {
			return err
		}
		for _, r := range recs {
			fmt.Printf("%6d  %s  %-8s %-16s %s\n", r.Index, r.Time.Format("2006-01-02 15:04:05"), r.Type, r.Actor, r.Note)
			for _, c := range r.Changes {
				fmt.Printf("          %-6s %s %q\n", c.Type, c.Kind, c.Name)
			}
		}
		return nil

	case "compact":
		s, err := openForWrite()
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Compact(*keep)

	case "import-legacy":
		in, err := loadLegacy(cfg)
		if err != nil {
			return err
		}
		res := confimport.Translate(in, nil)
		counts := map[model.Kind]int{}
		for _, op := range res.Ops {
			counts[op.Kind]++
		}
		kinds := make([]string, 0, len(counts))
		for k := range counts {
			kinds = append(kinds, string(k))
		}
		sort.Strings(kinds)
		fmt.Println("would create:")
		for _, k := range kinds {
			fmt.Printf("  %-18s %d\n", k, counts[model.Kind(k)])
		}
		if len(res.Notes) > 0 {
			fmt.Println("not carried over:")
			for _, n := range res.Notes {
				fmt.Println("  - " + n)
			}
		}
		if !*apply {
			fmt.Println("nothing written; repeat with --apply to write this into the model")
			return nil
		}
		s, err := openForWrite()
		if err != nil {
			return err
		}
		defer s.Close()
		if s.Current().Index() != 0 {
			return fmt.Errorf("the model already has content (record %d); the import only runs into an empty model", s.Current().Index())
		}
		actor := "cli"
		if u, err := user.Current(); err == nil {
			actor = "cli:" + u.Username
		}
		rec, err := s.Commit(context.Background(), actor, "import of the existing configuration", res.Ops)
		if err != nil {
			return fmt.Errorf("import rejected: %w", err)
		}
		fmt.Printf("imported as record %d\n", rec.Index)
		// The rules that are model objects now leave the old policy, so no
		// rule exists twice. The original is kept next to it.
		if res.Remaining != nil {
			path := firewallPolicyPathFor(cfg)
			orig, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(path+".before-import", orig, 0o600); err != nil {
				return err
			}
			out, err := json.MarshalIndent(res.Remaining, "", "  ")
			if err != nil {
				return err
			}
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, out, 0o600); err != nil {
				return err
			}
			if err := os.Rename(tmp, path); err != nil {
				return err
			}
			fmt.Printf("moved the imported rules out of %s (original kept as %s.before-import)\n", path, filepath.Base(path))
		}
		return nil
	}
	return fmt.Errorf("unknown config command: %s", args[0])
}

// loadLegacy reads the files directly; it never opens the firewall manager,
// which would touch the kernel or rewrite the policy file.
func loadLegacy(cfg config.Config) (confimport.Legacy, error) {
	in := confimport.Legacy{}
	in.Hostname, _ = os.Hostname()

	if data, err := os.ReadFile(firewallPolicyPathFor(cfg)); err == nil {
		var p firewall.Policy
		if err := json.Unmarshal(data, &p); err != nil {
			return in, fmt.Errorf("firewall policy: %w", err)
		}
		in.Firewall = &p
	} else if !errors.Is(err, os.ErrNotExist) {
		return in, err
	}

	// Users of users.json move into the model by themselves when the daemon
	// starts, with their passwords and second factors.

	// Live WireGuard devices are best effort: reading them needs privileges.
	devs, err := (&netops.Writer{}).ListWGDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: WireGuard devices not read (%v)\n", err)
		return in, nil
	}
	names := map[string]string{}
	if db, err := storage.Open(cfg.SQLitePath); err == nil {
		if meta, err := db.WGPeerMetaMap(context.Background()); err == nil {
			for k, m := range meta {
				names[k] = m.Name
			}
		}
		db.Close()
	}
	for _, d := range devs {
		t := confimport.Tunnel{WGDeviceInfo: d, PeerNames: names}
		if ifi, err := net.InterfaceByName(d.Name); err == nil {
			addrs, _ := ifi.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
					t.Addresses = append(t.Addresses, ipn.String())
				}
			}
		}
		in.Tunnels = append(in.Tunnels, t)
	}
	return in, nil
}
