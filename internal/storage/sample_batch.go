package storage

import (
	"context"
	"log"
	"sync"
	"time"
)

// Sample writes are batched.
//
// The engine records a sample per probe result, DNS query and loss event -
// several per second. As one autocommit INSERT each, every sample was its own
// WAL transaction: a commit frame, the table page and every index page
// rewritten, and an fsync, for ~40 bytes of data. Batching turns that into
// one transaction per second, which is what the "smart storage over raw
// persistence" rule asks for, at the cost of at most one second of samples on
// a crash. Reads of the samples table flush first, so callers never see a
// stale view.
const (
	sampleFlushEvery = time.Second
	sampleFlushAt    = 512    // rows: flush early when a burst fills the batch
	sampleBufferCap  = 20_000 // rows: drop beyond this if the DB is wedged
)

type pendingSample struct {
	session string
	Sample
}

type sampleBatcher struct {
	mu      sync.Mutex
	buf     []pendingSample
	dropped int

	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

func newSampleBatcher() *sampleBatcher {
	return &sampleBatcher{
		kick: make(chan struct{}, 1),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

// add queues a sample; it never blocks on the database.
func (b *sampleBatcher) add(session string, sm Sample) {
	b.mu.Lock()
	if len(b.buf) >= sampleBufferCap {
		b.dropped++
		b.mu.Unlock()
		return
	}
	b.buf = append(b.buf, pendingSample{session: session, Sample: sm})
	full := len(b.buf) >= sampleFlushAt
	b.mu.Unlock()
	if full {
		select {
		case b.kick <- struct{}{}:
		default:
		}
	}
}

// take swaps out the pending rows.
func (b *sampleBatcher) take() ([]pendingSample, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rows, dropped := b.buf, b.dropped
	b.buf, b.dropped = nil, 0
	return rows, dropped
}

// startSampleWriter runs the flush loop until Close.
func (s *Store) startSampleWriter() {
	b := s.samples
	go func() {
		defer close(b.done)
		t := time.NewTicker(sampleFlushEvery)
		defer t.Stop()
		for {
			select {
			case <-b.stop:
				if err := s.flushSamples(context.Background()); err != nil {
					log.Printf("storage: final sample flush: %v", err)
				}
				return
			case <-t.C:
			case <-b.kick:
			}
			if err := s.flushSamples(context.Background()); err != nil {
				log.Printf("storage: sample flush: %v", err)
			}
		}
	}()
}

// flushSamples writes every pending sample in one transaction. Rows that
// fail to write are dropped (and logged) rather than retried forever.
func (s *Store) flushSamples(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	rows, dropped := s.samples.take()
	if dropped > 0 {
		log.Printf("storage: dropped %d samples (write buffer full)", dropped)
	}
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO samples (session_id, kind, ts, label, value, failed) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		failed := 0
		if r.Failed {
			failed = 1
		}
		if _, err := stmt.ExecContext(ctx, r.session, r.Kind, r.TS.UnixMilli(), r.Label, r.Value, failed); err != nil {
			return err
		}
	}
	return tx.Commit()
}
