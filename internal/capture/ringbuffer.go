package capture

import (
	"sync"
	"time"
)

// PacketRecord is one entry in the live ring buffer. Payload is a defensive
// copy — callers retain ownership of their original byte slice.
type PacketRecord struct {
	Timestamp time.Time
	Iface     string
	Length    int
	Payload   []byte
}

// RingBuffer is the Layer-1 live storage from CLAUDE.md: a short-lived,
// fixed-capacity in-memory buffer of the most recent packets. When full,
// new writes overwrite the oldest entries. Used by anomaly analyzers and
// instant replay to look "just behind now" without touching disk.
//
// Safe for concurrent use.
type RingBuffer struct {
	mu    sync.RWMutex
	buf   []PacketRecord
	head  int  // index of next slot to write
	count int  // number of valid entries (<= cap)
	cap   int
}

// NewRingBuffer returns a buffer that retains up to capacity packets. A
// capacity of 0 or below is clamped to 1.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &RingBuffer{buf: make([]PacketRecord, capacity), cap: capacity}
}

// Push records a packet. The payload is copied so the caller may reuse the
// underlying byte slice.
func (r *RingBuffer) Push(iface string, payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	rec := PacketRecord{
		Timestamp: time.Now(),
		Iface:     iface,
		Length:    len(payload),
		Payload:   cp,
	}
	r.mu.Lock()
	r.buf[r.head] = rec
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
	r.mu.Unlock()
}

// Snapshot returns the buffer's contents in chronological order (oldest
// first). The returned slice is independent of the buffer.
func (r *RingBuffer) Snapshot() []PacketRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PacketRecord, r.count)
	start := r.head - r.count
	if start < 0 {
		start += r.cap
	}
	for i := 0; i < r.count; i++ {
		out[i] = r.buf[(start+i)%r.cap]
	}
	return out
}

// Since returns every record with Timestamp >= t, oldest first.
func (r *RingBuffer) Since(t time.Time) []PacketRecord {
	all := r.Snapshot()
	for i, rec := range all {
		if !rec.Timestamp.Before(t) {
			return all[i:]
		}
	}
	return nil
}

// Len returns the number of records currently stored.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Cap returns the buffer's fixed capacity.
func (r *RingBuffer) Cap() int { return r.cap }

// Reset empties the buffer without releasing its backing storage.
func (r *RingBuffer) Reset() {
	r.mu.Lock()
	for i := range r.buf {
		r.buf[i] = PacketRecord{}
	}
	r.head = 0
	r.count = 0
	r.mu.Unlock()
}
