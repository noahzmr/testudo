package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/privsep"
)

// nftRunnerArg selects the nft runner: a child of the privileged helper whose
// only job is to run the nft program on rulesets the helper hands it.
//
// The helper denies itself execve, so it cannot run nft. The runner is
// started before that restriction is installed, holds the same network
// capability, and accepts exactly three kinds of request (check, load, list
// one table) over a pipe that only the helper holds.
const nftRunnerArg = "__nft-runner"

const maxNftMessage = 64 << 20

// runNftRunner serves requests, one JSON document per line, until the helper
// closes the pipe.
func runNftRunner() error {
	// nft is a separate program without capabilities of its own. Raising
	// CAP_NET_ADMIN into the ambient set lets it inherit ours. Capabilities
	// belong to a thread, and the child is forked from the thread that runs
	// this loop, so the loop stays on it.
	runtime.LockOSThread()
	if err := privsep.RaiseAmbientNetAdmin(); err != nil {
		// As root this is not needed; otherwise loads will fail and say why.
		fmt.Fprintf(os.Stderr, "nft runner: cannot pass on the network capability: %v\n", err)
	}
	// The proxy is started through this binary again, which sheds what the
	// proxy must not have before it becomes the proxy.
	if exe, err := os.Executable(); err == nil {
		netops.ProxyWrapper = []string{exe, proxyExecArg}
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := json.NewEncoder(os.Stdout)
	for {
		line, err := readLine(in)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var req runnerRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = out.Encode(netops.NftResult{Error: "bad request"})
			continue
		}
		var res netops.NftResult
		switch {
		case req.Nft != nil:
			res = netops.RunNft(*req.Nft)
		case req.Frr != nil:
			res = netops.RunFrr(*req.Frr)
		case req.Proxy != nil:
			res = netops.RunProxy(*req.Proxy)
		default:
			res = netops.NftResult{Error: "empty request"}
		}
		if err := out.Encode(res); err != nil {
			return err
		}
	}
}

// runnerRequest is one job: for nft or for FRR's tools, never both.
type runnerRequest struct {
	Nft   *netops.NftRequest   `json:"nft,omitempty"`
	Frr   *netops.FrrRequest   `json:"frr,omitempty"`
	Proxy *netops.ProxyRequest `json:"proxy,omitempty"`
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		part, err := r.ReadSlice('\n')
		buf = append(buf, part...)
		if len(buf) > maxNftMessage {
			return nil, errors.New("message too large")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, err
	}
}

// nftRunnerProc is the helper's handle on its runner.
type nftRunnerProc struct {
	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startNftRunner() (*nftRunnerProc, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, nftRunnerArg)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &nftRunnerProc{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}, nil
}

// Run sends one nft request and waits for its answer.
func (p *nftRunnerProc) Run(req netops.NftRequest) netops.NftResult {
	return p.send(runnerRequest{Nft: &req})
}

// RunFrr sends one FRR request and waits for its answer.
func (p *nftRunnerProc) RunFrr(req netops.FrrRequest) netops.NftResult {
	return p.send(runnerRequest{Frr: &req})
}

// RunProxy sends one request for the proxy supervisor.
func (p *nftRunnerProc) RunProxy(req netops.ProxyRequest) netops.NftResult {
	return p.send(runnerRequest{Proxy: &req})
}

// send serialises requests: one at a time over the pipe.
func (p *nftRunnerProc) send(req runnerRequest) netops.NftResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	msg, err := json.Marshal(req)
	if err != nil {
		return netops.NftResult{Error: err.Error()}
	}
	if _, err := p.in.Write(append(msg, '\n')); err != nil {
		return netops.NftResult{Error: "nft runner is gone: " + err.Error()}
	}
	line, err := readLine(p.out)
	if err != nil {
		return netops.NftResult{Error: "nft runner is gone: " + err.Error()}
	}
	var res netops.NftResult
	if err := json.Unmarshal(line, &res); err != nil {
		return netops.NftResult{Error: "nft runner: bad answer"}
	}
	return res
}

func (p *nftRunnerProc) Close() {
	p.in.Close()
	_ = p.cmd.Wait()
}

// auditArgs keeps rulesets and routing configurations out of the audit log:
// they are large, derivable from the configuration history, and a routing
// configuration can contain session passwords. The row records size and hash.
func auditArgs(o netops.Op, body []byte) string {
	text := o.Nft + o.Frr
	if text == "" {
		return string(body)
	}
	sum := sha256.Sum256([]byte(text))
	out, _ := json.Marshal(map[string]any{"kind": o.Kind, "actor": o.Actor,
		"bytes": len(text), "sha256": hex.EncodeToString(sum[:])})
	return string(out)
}

// proxyExecArg makes this binary turn into the proxy: it keeps only the
// capability to bind low ports, then executes the command that follows.
// The runner holds CAP_NET_ADMIN to load rulesets; a proxy that terminates
// connections from the internet must not inherit that.
const proxyExecArg = "__proxy-exec"

func runProxyExec(args []string) error {
	if len(args) == 0 {
		return errors.New("proxy exec: no command")
	}
	runtime.LockOSThread()
	if err := privsep.KeepOnlyBindService(); err != nil {
		fmt.Fprintf(os.Stderr, "proxy exec: %v\n", err)
	}
	return syscall.Exec(args[0], args, os.Environ())
}
