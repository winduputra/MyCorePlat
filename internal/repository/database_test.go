package repository

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestOpenEmptyDSNReturnsError(t *testing.T) {
	_, err := Open(context.Background(), "", DefaultPoolSettings())
	if err == nil {
		t.Fatal("Open() expected error for empty DSN, got nil")
	}
}

func TestOpenUnreachableDSNFailsFast(t *testing.T) {
	// A syntactically valid MySQL DSN pointing at a closed port must fail the
	// ping rather than hang. Connect timeout in the DSN keeps this fast.
	dsn := "app:secret@tcp(127.0.0.1:1)/mycoreplat?parseTime=true&timeout=1s"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Open(ctx, dsn, DefaultPoolSettings())
	if err == nil {
		t.Fatal("Open() expected error for unreachable database, got nil")
	}
}

func TestPingNilHandleReturnsError(t *testing.T) {
	if err := Ping(context.Background(), nil); err == nil {
		t.Fatal("Ping(nil) expected error, got nil")
	}
}

func TestCloseNilHandleIsNoop(t *testing.T) {
	if err := Close(nil); err != nil {
		t.Fatalf("Close(nil) = %v, want nil", err)
	}
}

func TestDefaultPoolSettingsAreSane(t *testing.T) {
	p := DefaultPoolSettings()
	if p.MaxOpenConns <= 0 {
		t.Errorf("MaxOpenConns = %d, want > 0", p.MaxOpenConns)
	}
	if p.MaxIdleConns < 0 || p.MaxIdleConns > p.MaxOpenConns {
		t.Errorf("MaxIdleConns = %d, want 0..MaxOpenConns(%d)", p.MaxIdleConns, p.MaxOpenConns)
	}
	if p.ConnMaxLifetime <= 0 {
		t.Errorf("ConnMaxLifetime = %v, want > 0", p.ConnMaxLifetime)
	}
}

// TestOpenAgainstDevDatabase is an opt-in integration test. It runs only when
// DEV_DB_DSN is set (e.g. against the local dev MariaDB started by
// deploy/dev/docker-compose.yml), so the default `go test ./...` stays
// hermetic and does not require a database.
func TestOpenAgainstDevDatabase(t *testing.T) {
	dsn := os.Getenv("DEV_DB_DSN")
	if dsn == "" {
		t.Skip("DEV_DB_DSN not set; skipping live database integration test")
	}

	db, err := Open(context.Background(), dsn, DefaultPoolSettings())
	if err != nil {
		t.Fatalf("Open() against dev database failed: %v", err)
	}
	defer func() {
		if closeErr := Close(db); closeErr != nil {
			t.Errorf("Close() = %v, want nil", closeErr)
		}
	}()

	if err := Ping(context.Background(), db); err != nil {
		t.Errorf("Ping() against dev database failed: %v", err)
	}
}
