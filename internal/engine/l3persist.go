package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/storage"
)

// l3KeyframeEvery bounds how long an unchanged neighbour table or conntrack
// flow goes unrecorded: replay always finds a complete picture at most this
// far back, and conntrack packet/byte counters are sampled at this rate.
const l3KeyframeEvery = 10 * time.Minute

// l3Persist decides which neighbour and conntrack rows are worth a database
// write. The snapshotter used to store the whole neighbour table and every
// tracked connection every tick; on a quiet LAN about nine in ten neighbour
// rows were exact repeats, and a busy host's conntrack table is thousands of
// rows per tick. Only the snapshot goroutine touches it.
//
// Stored semantics:
//   - neighbours: the full table, written when any entry changed (added,
//     removed, new MAC, or became FAILED/INCOMPLETE or resolved again) and at
//     least every l3KeyframeEvery. The latest batch at or before t is the
//     table at t; NUD churn among healthy states is not a change.
//   - conntrack_samples: a flow is written when it first appears or its
//     state/NAT changes, and every flow at least every l3KeyframeEvery
//     (which refreshes its counters).
type l3Persist struct {
	neighKey string
	neighAt  time.Time

	ctSeen map[string]string // flow identity -> state|nat last written
	ctAt   time.Time         // last conntrack keyframe
}

// neighbours reports whether this tick's table must be written.
func (p *l3Persist) neighbours(rows []storage.NeighbourSample, now time.Time) bool {
	keys := make([]string, len(rows))
	for i, n := range rows {
		keys[i] = fmt.Sprintf("%s|%s|%s|%s|%s|%t", n.IP, n.MAC, n.Dev, n.Family, neighClass(n.State), n.Router)
	}
	sort.Strings(keys)
	key := strings.Join(keys, "\n")
	if key == p.neighKey && now.Sub(p.neighAt) < l3KeyframeEvery {
		return false
	}
	p.neighKey, p.neighAt = key, now
	return true
}

// neighClass folds the kernel's NUD states into what changes the meaning of
// the table. A healthy entry cycles REACHABLE → STALE → DELAY → PROBE →
// REACHABLE on its own every few seconds; keying on the raw state wrote the
// whole table on nearly every tick. Resolution failures stay distinct.
func neighClass(state string) string {
	switch strings.ToUpper(state) {
	case "FAILED":
		return "failed"
	case "INCOMPLETE":
		return "incomplete"
	}
	return "resolved"
}

// conntrack returns the rows to write this tick.
func (p *l3Persist) conntrack(rows []storage.ConntrackSample, now time.Time) []storage.ConntrackSample {
	keyframe := p.ctSeen == nil || now.Sub(p.ctAt) >= l3KeyframeEvery
	next := make(map[string]string, len(rows))
	out := rows[:0:0]
	for _, f := range rows {
		id := fmt.Sprintf("%s|%s:%d|%s:%d|%s|%s", f.Proto, f.OrigSrc, f.OrigSport, f.OrigDst, f.OrigDport, f.ReplySrc, f.ReplyDst)
		st := fmt.Sprintf("%s|%t", f.State, f.NATed)
		next[id] = st
		if keyframe || p.ctSeen[id] != st {
			out = append(out, f)
		}
	}
	p.ctSeen = next
	if keyframe {
		p.ctAt = now
	}
	return out
}
