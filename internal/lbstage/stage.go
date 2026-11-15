// Package lbstage applies the proxy configuration that internal/lbrender
// produces: it writes the proxy's files, keeps the proxy process running
// through the privileged side, and asks the proxy's own API whether it
// accepted what it was given.
package lbstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/lbrender"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner is the privileged side. *netops.Writer implements it.
type Runner interface {
	ProxyControl(mode netops.ProxyMode, configFile, logFile string) error
	ProxyState() (string, error)
}

// Stage implements confapply.Stage.
type Stage struct {
	// Runner may be nil on a node without privileges; then only a model
	// without proxy services can be applied.
	Runner Runner
	Locate func(*confstore.State) (siteID, nodeID string)
	// Dir holds the proxy's files; SecretsDir is the node's secret store.
	Dir, SecretsDir string
	// APIAddr is the loopback address of the proxy's API; AuthURL is where
	// it asks about logins.
	APIAddr, AuthURL string
	// Settle is how long the proxy gets to take over a new configuration.
	Settle time.Duration

	mu      sync.Mutex
	applied lbrender.Result
	static  string // the static configuration the running proxy was started with
}

func (s *Stage) Name() string { return "load-balancer" }

func (s *Stage) options(st *confstore.State) lbrender.Options {
	opt := lbrender.Options{Dir: s.Dir, SecretsDir: s.SecretsDir, APIAddr: s.APIAddr, AuthURL: s.AuthURL}
	if s.Locate != nil {
		opt.SiteID, opt.NodeID = s.Locate(st)
	}
	return opt
}

// Render builds the proxy configuration for this node.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	res, err := lbrender.Render(st, s.options(st))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", " ")
}

// Redact shows a person the two configuration files instead of the JSON
// envelope around them.
func (s *Stage) Redact(artifact []byte) []byte {
	var res lbrender.Result
	if json.Unmarshal(artifact, &res) != nil || res.Empty {
		return nil
	}
	return []byte("# " + lbrender.StaticFile + "\n" + res.Files[lbrender.StaticFile] +
		"\n# " + lbrender.DynamicFile + "\n" + res.Files[lbrender.DynamicFile])
}

func decode(raw []byte) (lbrender.Result, error) {
	var res lbrender.Result
	err := json.Unmarshal(raw, &res)
	return res, err
}

// Check makes sure the proxy can be run here. The proxy has no offline
// validator for its dynamic configuration; what it makes of a configuration
// is checked after the apply, and a refusal rolls the change back.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil || res.Empty {
		return err
	}
	if s.Runner == nil {
		return errors.New("the load balancer is not available on this node (no privileges)")
	}
	state, err := s.Runner.ProxyState()
	if err != nil {
		return err
	}
	if state == "missing" {
		return errors.New("the proxy (traefik) is not installed on this node")
	}
	return nil
}

// Apply writes the files and makes the proxy run with them.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	conf := filepath.Join(s.Dir, lbrender.StaticFile)
	if res.Empty {
		// Nothing to serve. Stop a proxy this program started, and leave a
		// node that never had one untouched.
		if _, err := os.Stat(conf); err != nil || s.Runner == nil {
			s.applied = res
			return nil
		}
		if err := s.Runner.ProxyControl(netops.ProxyStop, "", ""); err != nil {
			return err
		}
		_ = os.Remove(conf)
		s.applied, s.static = res, ""
		return nil
	}
	if s.Runner == nil {
		return errors.New("the load balancer is not available on this node (no privileges)")
	}
	for _, sub := range []string{"", "dynamic", "certs"} {
		if err := os.MkdirAll(filepath.Join(s.Dir, sub), 0o700); err != nil {
			return err
		}
	}
	// The dynamic file last: it is the one the proxy watches, and by then
	// the certificates it names exist.
	names := make([]string, 0, len(res.Files))
	for name := range res.Files {
		if name != lbrender.DynamicFile {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range append(names, lbrender.DynamicFile) {
		path := filepath.Join(s.Dir, name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(res.Files[name]), 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	// Certificates no router uses any more.
	if entries, err := os.ReadDir(filepath.Join(s.Dir, "certs")); err == nil {
		for _, e := range entries {
			if _, used := res.Files["certs/"+e.Name()]; !used {
				_ = os.Remove(filepath.Join(s.Dir, "certs", e.Name()))
			}
		}
	}
	mode := netops.ProxyEnsure
	if state, _ := s.Runner.ProxyState(); state != "running" || s.static != res.Static {
		// Entry points are static: a new or changed listener needs a
		// restart. Routers, services and certificates do not.
		mode = netops.ProxyRestart
	}
	if err := s.Runner.ProxyControl(mode, conf, filepath.Join(s.Dir, "traefik.log")); err != nil {
		return err
	}
	s.applied, s.static = res, res.Static
	return nil
}

func (s *Stage) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.APIAddr+path, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy API %s: %s", path, res.Status)
	}
	if out == nil {
		return nil
	}
	if text, ok := out.(*string); ok {
		*text = string(body)
		return nil
	}
	return json.Unmarshal(body, out)
}

type apiRouter struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Error  []string `json:"error"`
}

// Healthy waits for the proxy to take over the configuration and reports
// what it refused. Every router of the artifact has to be there and enabled.
func (s *Stage) Healthy(ctx context.Context) error {
	s.mu.Lock()
	res := s.applied
	s.mu.Unlock()
	if res.Empty || len(res.Files) == 0 {
		return nil
	}
	settle := s.Settle
	if settle <= 0 {
		settle = 10 * time.Second
	}
	var last error
	for deadline := time.Now().Add(settle); ; time.Sleep(200 * time.Millisecond) {
		last = s.accepted(ctx, res)
		if last == nil || time.Now().After(deadline) {
			return last
		}
		var refused *refusedError
		if errors.As(last, &refused) {
			return last // the proxy read the configuration and said no; waiting does not help
		}
	}
}

type refusedError struct{ msgs []string }

func (e *refusedError) Error() string {
	return "the proxy refused part of the configuration: " + strings.Join(e.msgs, "; ")
}

func (s *Stage) accepted(ctx context.Context, res lbrender.Result) error {
	if err := s.get(ctx, "/ping", nil); err != nil {
		return fmt.Errorf("the proxy does not answer: %w", err)
	}
	have := map[string]apiRouter{}
	for _, family := range []string{"http", "tcp", "udp"} {
		var list []apiRouter
		if err := s.get(ctx, "/api/"+family+"/routers", &list); err != nil {
			return err
		}
		for _, r := range list {
			have[strings.TrimSuffix(r.Name, "@file")] = r
		}
	}
	var refused, missing []string
	for name := range res.Routers {
		r, ok := have[name]
		switch {
		case !ok:
			missing = append(missing, name)
		case r.Status != "enabled" || len(r.Error) > 0:
			refused = append(refused, fmt.Sprintf("%s: %s", name, strings.Join(r.Error, ", ")))
		}
	}
	sort.Strings(refused)
	sort.Strings(missing)
	if len(refused) > 0 {
		return &refusedError{refused}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the proxy has not loaded: %s", strings.Join(missing, ", "))
	}
	return nil
}
