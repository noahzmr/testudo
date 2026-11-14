package netops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// The full packet-filter renderer produces nftables text, and text is loaded
// with the nft program. Three operations exist and nothing else is ever run:
// check a ruleset, load a ruleset, list one table as JSON.

const (
	// OpNftApply loads a ruleset (Op.Nft) as one transaction.
	OpNftApply OpKind = "nft_apply"
	// OpQueryNftCheck validates a ruleset (Op.Nft) without loading it.
	OpQueryNftCheck OpKind = "nft_check"
	// OpQueryNftList returns `nft -j list table <Family> <Table>`.
	OpQueryNftList OpKind = "nft_list"
	// OpQueryNftAvailable reports whether nft can be run with privileges.
	OpQueryNftAvailable OpKind = "nft_available"
)

// NftMode selects one of the three things the runner does.
type NftMode string

const (
	NftCheck NftMode = "check"
	NftLoad  NftMode = "load"
	NftList  NftMode = "list"
)

// NftRequest is one job for the runner.
type NftRequest struct {
	Mode    NftMode `json:"mode"`
	Ruleset string  `json:"ruleset,omitempty"`
	Family  string  `json:"family,omitempty"`
	Table   string  `json:"table,omitempty"`
}

// NftResult is the runner's answer.
type NftResult struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ErrNftTableMissing is returned by NftListTable when the table does not exist.
var ErrNftTableMissing = errors.New("nft: table does not exist")

var nftPaths = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"}

func nftBinary() (string, error) {
	for _, p := range nftPaths {
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath("nft")
}

func validIdent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// RunNft executes one request with the nft program. The argument vector is
// fixed per mode; the ruleset only ever travels on standard input.
func RunNft(req NftRequest) NftResult {
	bin, err := nftBinary()
	if err != nil {
		return NftResult{Error: "nft is not installed"}
	}
	var args []string
	switch req.Mode {
	case NftCheck:
		args = []string{"-c", "-f", "-"}
	case NftLoad:
		args = []string{"-f", "-"}
	case NftList:
		if !validIdent(req.Family) || !validIdent(req.Table) {
			return NftResult{Error: "bad table name"}
		}
		args = []string{"-j", "list", "table", req.Family, req.Table}
	default:
		return NftResult{Error: fmt.Sprintf("unknown nft mode %q", req.Mode)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(req.Ruleset)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return NftResult{Error: msg}
	}
	return NftResult{Output: out.String()}
}

// nftRunner, when set, replaces direct execution. The privileged helper
// installs one that talks to its runner process, because the helper itself
// may not execute programs.
var (
	nftRunnerMu sync.RWMutex
	nftRunner   func(NftRequest) NftResult
)

// SetNftRunner routes every nft request of this process through fn.
func SetNftRunner(fn func(NftRequest) NftResult) {
	nftRunnerMu.Lock()
	nftRunner = fn
	nftRunnerMu.Unlock()
}

func runNft(req NftRequest) (string, error) {
	nftRunnerMu.RLock()
	fn := nftRunner
	nftRunnerMu.RUnlock()
	if fn == nil {
		fn = RunNft
	}
	res := fn(req)
	if res.Error != "" {
		if req.Mode == NftList && strings.Contains(res.Error, "No such file or directory") {
			return "", ErrNftTableMissing
		}
		return "", errors.New("nft: " + res.Error)
	}
	return res.Output, nil
}

// nftProbe is a ruleset that cannot be checked without talking to the
// kernel: creating and deleting a table makes nft load its cache, which
// needs the same privilege as loading a ruleset. An empty ruleset would
// pass for anyone.
const nftProbe = "table inet testudo_probe\ndelete table inet testudo_probe\n"

// nftAvailableDirect reports whether this process can load rulesets: nft is
// installed and may talk to the kernel. The probe runs in check mode, so it
// changes nothing.
func nftAvailableDirect() bool {
	_, err := runNft(NftRequest{Mode: NftCheck, Ruleset: nftProbe})
	return err == nil
}

// NftAvailable reports whether rulesets can be loaded, here or in the helper.
func (w *Writer) NftAvailable() bool {
	var ok bool
	return w.queryInto(Op{Kind: OpQueryNftAvailable}, &ok) == nil && ok
}

// NftCheck validates a ruleset without changing anything.
func (w *Writer) NftCheck(ruleset string) error {
	var res string
	return w.queryInto(Op{Kind: OpQueryNftCheck, Nft: ruleset}, &res)
}

// NftApply loads a ruleset as one transaction. It is a mutation: gated by
// the write switch and audited.
func (w *Writer) NftApply(ruleset string) error {
	if !w.AllowWrites {
		return fmt.Errorf("nft apply: writes are disabled")
	}
	return w.mutate(Op{Kind: OpNftApply, Nft: ruleset})
}

// NftListTable returns the JSON listing of one table.
func (w *Writer) NftListTable(family, table string) ([]byte, error) {
	var out string
	if err := w.queryInto(Op{Kind: OpQueryNftList, Family: family, Table: table}, &out); err != nil {
		if strings.Contains(err.Error(), ErrNftTableMissing.Error()) {
			return nil, ErrNftTableMissing
		}
		return nil, err
	}
	return []byte(out), nil
}

func nftQueryDirect(op Op) ([]byte, error) {
	switch op.Kind {
	case OpQueryNftAvailable:
		return json.Marshal(nftAvailableDirect())
	case OpQueryNftCheck:
		_, err := runNft(NftRequest{Mode: NftCheck, Ruleset: op.Nft})
		return marshalResult("ok", err)
	default:
		return marshalResult(runNft(NftRequest{Mode: NftList, Family: op.Family, Table: op.Table}))
	}
}
