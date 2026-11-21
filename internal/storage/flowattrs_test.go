package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestFlowAttrsSurviveAndOldDatabasesMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// A database written before flows carried attributions.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE flows (session_id TEXT NOT NULL, iface TEXT NOT NULL DEFAULT '', a_ip TEXT NOT NULL,
		a_port INTEGER NOT NULL, b_ip TEXT NOT NULL, b_port INTEGER NOT NULL, proto TEXT NOT NULL, packets INTEGER NOT NULL,
		bytes INTEGER NOT NULL, bytes_a_to_b INTEGER NOT NULL, bytes_b_to_a INTEGER NOT NULL, first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL, process TEXT NOT NULL DEFAULT '', dns_name TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (session_id, iface, a_ip, a_port, b_ip, b_port, proto));
		INSERT INTO flows VALUES ('s', 'eth0', '10.0.0.1', 1, '10.0.0.2', 2, 'tcp', 1, 1, 1, 0, 0, 0, '', '');`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open an old database: %v", err)
	}
	defer st.Close()
	ctx := context.Background()
	rows, err := st.FlowsBySession(ctx, "s", 10)
	if err != nil || len(rows) != 1 || rows[0].Attrs != "" {
		t.Fatalf("old row: %+v %v", rows, err)
	}
	now := time.Now()
	row := FlowRow{Iface: "wg0", AIP: "10.8.0.2", APort: 5000, BIP: "10.1.0.5", BPort: 443, Proto: "tcp", Packets: 2, Bytes: 100,
		FirstSeen: now, LastSeen: now, Attrs: `{"tunnel":"roadwarriors","user":"alice"}`}
	if err := st.UpsertFlow(ctx, "s", row); err != nil {
		t.Fatal(err)
	}
	// A later flush that knows nothing more keeps what was known.
	row.Attrs = ""
	if err := st.UpsertFlow(ctx, "s", row); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.FlowsBySession(ctx, "s", 10)
	for _, r := range rows {
		if r.Iface == "wg0" && (r.Attrs != `{"tunnel":"roadwarriors","user":"alice"}` || r.Packets != 4) {
			t.Errorf("attributed row: %+v", r)
		}
	}
}

func TestOldFlowsAreRetired(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now()
	for i, age := range []time.Duration{time.Hour, RawSampleRetention + time.Hour} {
		seen := now.Add(-age)
		st.UpsertFlow(ctx, "s", FlowRow{Iface: "eth0", AIP: "10.0.0.1", APort: uint16(i + 1), BIP: "10.0.0.2", BPort: 80, Proto: "tcp",
			FirstSeen: seen, LastSeen: seen})
	}
	if err := st.Retain(ctx, now); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.FlowsBySession(ctx, "s", 10)
	if len(rows) != 1 || rows[0].APort != 1 {
		t.Errorf("after retention: %+v", rows)
	}
}
