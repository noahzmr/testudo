package svcstage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/svcrender"
)

// Lease is one address Kea has handed out.
type Lease struct {
	Address   string    `json:"address"`
	HWAddress string    `json:"hw_address,omitempty"`
	DUID      string    `json:"duid,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	SubnetID  uint32    `json:"subnet_id"`
	Expires   time.Time `json:"expires"`
	// State is Kea's: 0 assigned, 1 declined, 2 expired and reclaimed.
	State int  `json:"state"`
	V6    bool `json:"v6,omitempty"`
}

// Active reports whether the lease holds its address at now.
func (l Lease) Active(now time.Time) bool { return l.State == 0 && l.Expires.After(now) }

// keaCommand sends one command to a Kea control socket and decodes the
// arguments of the answer into out.
func keaCommand(ctx context.Context, socket, command string, out any) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(conn, `{"command": %q}`, command); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(conn, 64<<20))
	if err != nil && len(raw) == 0 {
		return err
	}
	var resp struct {
		Result    int             `json:"result"`
		Text      string          `json:"text"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("kea: %s: %w", command, err)
	}
	switch resp.Result {
	case 0:
	case 3: // empty
		return nil
	default:
		return fmt.Errorf("kea: %s: %s", command, resp.Text)
	}
	if out != nil && len(resp.Arguments) > 0 {
		return json.Unmarshal(resp.Arguments, out)
	}
	return nil
}

// Leases asks a running Kea server for every lease it holds.
func Leases(ctx context.Context, runDir string, v6 bool) ([]Lease, error) {
	sock, cmd := svcrender.Kea4Socket, "lease4-get-all"
	if v6 {
		sock, cmd = svcrender.Kea6Socket, "lease6-get-all"
	}
	var args struct {
		Leases []struct {
			IP       string `json:"ip-address"`
			HW       string `json:"hw-address"`
			DUID     string `json:"duid"`
			Hostname string `json:"hostname"`
			SubnetID uint32 `json:"subnet-id"`
			CLTT     int64  `json:"cltt"`
			Valid    int64  `json:"valid-lft"`
			State    int    `json:"state"`
			Type     string `json:"type"`
		} `json:"leases"`
	}
	if err := keaCommand(ctx, filepath.Join(runDir, sock), cmd, &args); err != nil {
		return nil, err
	}
	out := make([]Lease, 0, len(args.Leases))
	for _, l := range args.Leases {
		if v6 && l.Type != "" && l.Type != "IA_NA" {
			continue // delegated prefixes have no host name
		}
		out = append(out, Lease{Address: l.IP, HWAddress: l.HW, DUID: l.DUID, Hostname: strings.TrimSuffix(strings.ToLower(l.Hostname), "."),
			SubnetID: l.SubnetID, Expires: time.Unix(l.CLTT+l.Valid, 0), State: l.State, V6: v6})
	}
	return out, nil
}

// LeaseTTL is the time-to-live of a client's name in the resolver.
const LeaseTTL = 300

// DesiredNames returns the names of the clients that hold a lease in a
// scope that registers them: name to addresses. A name the model gives
// (a record or a reservation) is never taken over by a client, and a name
// outside the scope's domain is ignored.
func DesiredNames(res svcrender.Result, leases []Lease, now time.Time) map[string][]string {
	scopes := map[string]svcrender.Scope{}
	for _, s := range res.Scopes {
		scopes[fmt.Sprintf("%v/%d", s.V6, s.SubnetID)] = s
	}
	static := map[string]bool{}
	for _, n := range res.StaticNames {
		static[n] = true
	}
	out := map[string][]string{}
	for _, l := range leases {
		s, ok := scopes[fmt.Sprintf("%v/%d", l.V6, l.SubnetID)]
		if !ok || !s.Register || !l.Active(now) || l.Hostname == "" || static[l.Hostname] {
			continue
		}
		if !strings.HasSuffix(l.Hostname, "."+s.Domain) {
			continue
		}
		out[l.Hostname] = append(out[l.Hostname], l.Address)
	}
	for n := range out {
		sort.Strings(out[n])
	}
	return out
}

// Names keeps the names of DHCP clients in the resolver: in the include
// file it reads when it starts, and in the running resolver through its
// control socket, so that a change needs no reload.
type Names struct {
	RunDir string

	mu      sync.Mutex
	current map[string][]string // nil until the first sync
}

// Sync makes the resolver answer exactly want.
func (n *Names) Sync(ctx context.Context, want map[string][]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Keep a copy: the caller may change its map afterwards.
	cp := make(map[string][]string, len(want))
	for k, v := range want {
		cp[k] = append([]string(nil), v...)
	}
	want = cp
	if err := n.writeFile(want); err != nil {
		return err
	}
	if n.current == nil {
		// What the resolver holds from an earlier run is unknown: start
		// it over from the file.
		if err := n.control(ctx, "reload"); err != nil {
			return err
		}
		n.current = want
		return nil
	}
	for name, old := range n.current {
		if same(old, want[name]) {
			continue
		}
		if err := n.control(ctx, "local_data_remove "+name+"."); err != nil {
			return err
		}
		for _, a := range old {
			if ip := net.ParseIP(a); ip != nil {
				if err := n.control(ctx, "local_data_remove "+svcrender.PTRName(ip)); err != nil {
					return err
				}
			}
		}
	}
	for name, addrs := range want {
		if same(addrs, n.current[name]) {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				for _, rr := range svcrender.AddressRecords(name, ip, LeaseTTL) {
					if err := n.control(ctx, "local_data "+rr); err != nil {
						return err
					}
				}
			}
		}
	}
	n.current = want
	return nil
}

// Forget makes the next Sync start over, after the resolver restarted.
func (n *Names) Forget() {
	n.mu.Lock()
	n.current = nil
	n.mu.Unlock()
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (n *Names) writeFile(want map[string][]string) error {
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Names of DHCP clients, kept by testudo.\n")
	for _, name := range names {
		for _, a := range want[name] {
			if ip := net.ParseIP(a); ip != nil {
				for _, rr := range svcrender.AddressRecords(name, ip, LeaseTTL) {
					fmt.Fprintf(&b, "local-data: '%s'\n", rr)
				}
			}
		}
	}
	p := filepath.Join(n.RunDir, svcrender.LeaseNames)
	if old, err := os.ReadFile(p); err == nil && string(old) == b.String() {
		return nil
	}
	if err := os.WriteFile(p+".tmp", []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// control sends one command to Unbound's control socket (the plain
// protocol unbound-control speaks without certificates).
func (n *Names) control(ctx context.Context, command string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", filepath.Join(n.RunDir, svcrender.UnboundCtl))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "UBCT1 %s\n", command); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	var reply []string
	for sc.Scan() {
		reply = append(reply, sc.Text())
	}
	if len(reply) == 0 || reply[0] != "ok" {
		return fmt.Errorf("unbound: %s: %s", strings.Fields(command)[0], strings.Join(reply, " "))
	}
	return nil
}
