package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestBaselineMigrationVersion(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"001120_baseline.up.sql", "001120_baseline.down.sql", "001121_next.up.sql"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("-- noop"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := baselineMigrationVersion(dir); got != 1120 {
		t.Fatalf("baselineMigrationVersion = %d, want 1120", got)
	}
	if got := baselineMigrationVersion(t.TempDir()); got != 0 {
		t.Fatalf("no baseline file should yield 0, got %d", got)
	}
	if got := baselineMigrationVersion("/no/such/dir/xyz"); got != 0 {
		t.Fatalf("missing dir should yield 0, got %d", got)
	}
}

// The shipped migrations start from one baseline (RFC-053).
func TestBaselineMigrationVersion_RealDir(t *testing.T) {
	dir := filepath.Join("..", "..", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("migrations dir not present: %v", err)
	}
	if got := baselineMigrationVersion(dir); got == 0 {
		t.Fatal("the migrations directory has no NNNNNN_baseline.up.sql")
	}
}

func TestSchemaVersionProblem(t *testing.T) {
	const latest, baseline = 1125, 1120
	cases := []struct {
		name     string
		version  int64
		dirty    bool
		baseline int64
		want     string // substring of the error; "" = no error
	}{
		{"up to date", latest, false, baseline, ""},
		{"ahead of this binary (rolling deploy)", latest + 1, false, baseline, ""},
		{"behind, above the baseline", baseline, false, baseline, "schema is behind"},
		{"fresh database", 0, false, baseline, "schema is behind"},
		{"older than the baseline", 1010, false, baseline, "older than the migration baseline 1120"},
		{"older than the baseline and dirty", 1010, true, baseline, "pre-baseline-001120"},
		{"dirty above the baseline", 1122, true, baseline, "DIRTY"},
		{"no baseline in the directory", 1010, false, 0, "schema is behind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schemaVersionProblem(tc.version, tc.dirty, latest, tc.baseline)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
