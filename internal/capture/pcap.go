package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PCAPWriter writes the live ring buffer to a rotated set of pcap files in
// dir/<session>/. Files are rotated when they exceed MaxSize bytes. The
// writer is **opt-in** — call Trigger() to begin a capture window for the
// configured duration; idle the rest of the time so we don't fill disks.
type PCAPWriter struct {
	Dir       string
	SessionID string
	MaxSize   int64
	Ring      *RingBuffer

	mu       sync.Mutex
	active   bool
	until    time.Time
	file     *os.File
	writer   *pcapgo.Writer
	written  int64
	rotated  int
}

func NewPCAPWriter(dir, sessionID string, maxSize int64, ring *RingBuffer) *PCAPWriter {
	if maxSize <= 0 {
		maxSize = 64 * 1024 * 1024
	}
	return &PCAPWriter{
		Dir: dir, SessionID: sessionID, MaxSize: maxSize, Ring: ring,
	}
}

// Trigger opens a new capture window of length d. If a window is already
// active, the deadline is extended (whichever is later wins). Safe to call
// from any goroutine.
func (w *PCAPWriter) Trigger(d time.Duration) error {
	if w == nil || w.Ring == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	deadline := time.Now().Add(d)
	if w.active {
		if deadline.After(w.until) {
			w.until = deadline
		}
		return nil
	}
	if err := w.openNext(); err != nil {
		return err
	}
	w.active = true
	w.until = deadline
	return nil
}

// Run consumes from the ring on a tick and flushes new packets to disk for
// as long as the capture window is open. Returns when ctx ends.
func (w *PCAPWriter) Run(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	var lastSeen time.Time
	for {
		select {
		case <-ctx.Done():
			w.close()
			return
		case <-t.C:
		}
		w.mu.Lock()
		if !w.active {
			w.mu.Unlock()
			continue
		}
		if time.Now().After(w.until) {
			w.closeLocked()
			w.mu.Unlock()
			continue
		}
		w.mu.Unlock()
		recs := w.Ring.Since(lastSeen)
		if len(recs) == 0 {
			continue
		}
		lastSeen = recs[len(recs)-1].Timestamp.Add(time.Nanosecond)
		_ = w.writeBatch(recs)
	}
}

func (w *PCAPWriter) writeBatch(recs []PacketRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writer == nil {
		return nil
	}
	for _, r := range recs {
		if w.written >= w.MaxSize {
			if err := w.rotateLocked(); err != nil {
				return err
			}
		}
		hdr := gopacket.CaptureInfo{
			Timestamp:     r.Timestamp,
			CaptureLength: r.Length,
			Length:        r.Length,
		}
		if err := w.writer.WritePacket(hdr, r.Payload); err != nil {
			return err
		}
		w.written += int64(len(r.Payload)) + 16
	}
	return nil
}

func (w *PCAPWriter) openNext() error {
	dir := filepath.Join(w.Dir, w.SessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir pcap: %w", err)
	}
	name := fmt.Sprintf("capture-%s-%03d.pcap", time.Now().UTC().Format("20060102-150405"), w.rotated)
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		return fmt.Errorf("pcap header: %w", err)
	}
	w.file = f
	w.writer = pw
	w.written = 0
	w.rotated++
	return nil
}

func (w *PCAPWriter) rotateLocked() error {
	if w.file != nil {
		_ = w.file.Close()
	}
	w.file = nil
	w.writer = nil
	return w.openNext()
}

func (w *PCAPWriter) closeLocked() {
	if w.file != nil {
		_ = w.file.Close()
	}
	w.file = nil
	w.writer = nil
	w.active = false
}

func (w *PCAPWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked()
}
