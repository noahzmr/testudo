package flowattr

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Access is one request the proxy passed on, from its access log.
type Access struct {
	Client  string    `json:"client"`  // ip:port of the client's connection
	Router  string    `json:"router"`  // the proxy's router name, without the provider
	Host    string    `json:"host"`    // the request's host
	Backend string    `json:"backend"` // ip:port the request went to
	Time    time.Time `json:"time"`
}

// accessLine is the part of Traefik's JSON access log this reads.
type accessLine struct {
	ClientAddr  string    `json:"ClientAddr"`
	RouterName  string    `json:"RouterName"`
	RequestHost string    `json:"RequestHost"`
	ServiceAddr string    `json:"ServiceAddr"`
	ServiceURL  string    `json:"ServiceURL"`
	StartUTC    time.Time `json:"StartUTC"`
}

// ParseAccess reads one line of the proxy's access log.
func ParseAccess(line []byte) (Access, bool) {
	var l accessLine
	if json.Unmarshal(line, &l) != nil || l.ClientAddr == "" {
		return Access{}, false
	}
	backend := l.ServiceAddr
	if backend == "" {
		backend = strings.TrimPrefix(strings.TrimPrefix(l.ServiceURL, "http://"), "https://")
	}
	router, _, _ := strings.Cut(l.RouterName, "@")
	return Access{Client: l.ClientAddr, Router: router, Host: l.RequestHost, Backend: backend, Time: l.StartUTC}, true
}

// AccessLog follows the proxy's access log and keeps the recent requests.
// It reads what was appended since the last call; a log that was truncated
// or replaced is read from the start.
type AccessLog struct {
	Path string
	// Keep is how long a request is remembered (default five minutes);
	// Max bounds how many (default 20000).
	Keep time.Duration
	Max  int

	mu      sync.Mutex
	offset  int64
	inode   uint64
	entries []Access
}

// Read takes in what was appended and returns the requests remembered.
func (a *AccessLog) Read(now time.Time) []Access {
	a.mu.Lock()
	defer a.mu.Unlock()
	keep, max := a.Keep, a.Max
	if keep <= 0 {
		keep = 5 * time.Minute
	}
	if max <= 0 {
		max = 20000
	}
	if f, err := os.Open(a.Path); err == nil {
		if st, err := f.Stat(); err == nil {
			ino := inodeOf(st)
			if st.Size() < a.offset || ino != a.inode {
				a.offset, a.inode = 0, ino
			}
			if _, err := f.Seek(a.offset, io.SeekStart); err == nil {
				r := bufio.NewReaderSize(f, 64<<10)
				for {
					line, err := r.ReadBytes('\n')
					if err != nil {
						break // a partial last line is read next time
					}
					a.offset += int64(len(line))
					if e, ok := ParseAccess(line); ok {
						a.entries = append(a.entries, e)
					}
				}
			}
		}
		f.Close()
	}
	cut := 0
	for cut < len(a.entries) && (now.Sub(a.entries[cut].Time) > keep || len(a.entries)-cut > max) {
		cut++
	}
	a.entries = a.entries[cut:]
	return append([]Access(nil), a.entries...)
}
