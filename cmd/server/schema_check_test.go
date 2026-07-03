package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLatestMigrationVersion(t *testing.T) {
	dir := t.TempDir()
	// migrations (varied widths + a matching down + non-migration noise)
	for _, name := range []string{
		"000001_init.up.sql", "000001_init.down.sql",
		"000042_add_thing.up.sql",
		"000183_user_federated_identity.up.sql", "000183_user_federated_identity.down.sql",
		"README.md", "seed", // ignored
	} {
		if name == "seed" {
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("-- noop"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := latestMigrationVersion(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 183 {
		t.Fatalf("latestMigrationVersion = %d, want 183", got)
	}
}

func TestLatestMigrationVersion_EmptyDir(t *testing.T) {
	got, err := latestMigrationVersion(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Fatalf("empty dir should yield 0, got %d", got)
	}
}

func TestLatestMigrationVersion_MissingDir(t *testing.T) {
	if _, err := latestMigrationVersion("/no/such/dir/xyz"); err == nil {
		t.Fatal("expected an error for a missing dir (caller treats it as skip)")
	}
}

// The real migrations dir must parse to the highest shipped version (guards the
// regex + that the check sees the actual migrations in the repo/image).
func TestLatestMigrationVersion_RealDir(t *testing.T) {
	dir := filepath.Join("..", "..", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("migrations dir not present: %v", err)
	}
	got, err := latestMigrationVersion(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got < 183 {
		t.Fatalf("real migrations latest = %d, expected >= 183", got)
	}
}
