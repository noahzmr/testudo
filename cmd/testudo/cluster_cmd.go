package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noahzmr/testudo/internal/cluster"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/secrets"
)

// cmdCluster handles `testudo cluster recover`. Everything else about a
// cluster (init, join, tokens, members) goes through the API of the running
// daemon, because it needs the daemon's connections.
func cmdCluster(args []string) error {
	if len(args) == 0 || args[0] != "recover" {
		return fmt.Errorf("usage: testudo cluster recover --unsafe --cluster-raft ADDR [--storage DIR] [--node-name NAME]")
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("cluster recover", flag.ExitOnError)
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	raftAddr := fs.String("cluster-raft", "", "the consensus transport address this member is started with")
	name := fs.String("node-name", "", "this member's name (default: the host name)")
	unsafe := fs.Bool("unsafe", false, "required: confirms that the lost members are gone for good")
	_ = fs.Parse(args[1:])
	if !*unsafe || *raftAddr == "" {
		fmt.Fprintln(os.Stderr, `cluster recover makes this member a cluster of one from what it has on disk.

Use it only when the majority of voters is lost for good and the cluster
can decide nothing any more. What the lost members had agreed on and this
one never received is gone. If one of them comes back, do not start it as
it is: wipe its storage and join it again.

The daemon on this node must be stopped. Repeat with --unsafe and
--cluster-raft to go ahead.`)
		return fmt.Errorf("not confirmed")
	}
	cfg.StorageDir = *storageDir
	id := *name
	if id == "" {
		id, _ = os.Hostname()
	}
	store, err := confstore.Open(engine.ConfigDir(cfg))
	if err != nil {
		return fmt.Errorf("open the model (is the daemon still running?): %w", err)
	}
	defer store.Close()
	mgr, err := cluster.NewManager(cluster.Config{ID: id, Dir: filepath.Join(cfg.StorageDir, "cluster"),
		RaftBind: *raftAddr, APIBind: *raftAddr, Store: store, Secrets: secrets.Store{Dir: filepath.Join(cfg.StorageDir, "secrets")}})
	if err != nil {
		return err
	}
	if err := mgr.RecoverAlone(); err != nil {
		return err
	}
	fmt.Printf("this member (%s) is now a cluster of one at model record %d\n", id, store.Current().Index())
	fmt.Println("start the daemon; add the other sites again with fresh join tokens")
	return nil
}
