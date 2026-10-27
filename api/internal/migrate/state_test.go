package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func migs(versions ...int64) []Migration {
	out := make([]Migration, 0, len(versions))
	for _, v := range versions {
		out = append(out, Migration{Version: v, Name: "m", UpPath: "x.up.sql"})
	}
	return out
}

func versionsOf(ms []Migration) []int64 {
	out := []int64{}
	for _, m := range ms {
		out = append(out, m.Version)
	}
	return out
}

func set(vs ...int64) map[int64]bool {
	s := map[int64]bool{}
	for _, v := range vs {
		s[v] = true
	}
	return s
}

func TestResolve(t *testing.T) {
	baseline := []Migration{{Version: 100, Name: "baseline", UpPath: "b.up.sql"}, {Version: 110, Name: "m", UpPath: "x.up.sql"}, {Version: 120, Name: "m", UpPath: "x.up.sql"}}
	cases := []struct {
		name        string
		st          dbState
		migs        []Migration
		wantRecord  []int64
		wantPending []int64
		wantUnknown []int64
		wantErr     any
	}{
		{name: "fresh database: everything pending", st: dbState{Applied: set()}, migs: migs(1, 2, 3),
			wantRecord: []int64{}, wantPending: []int64{1, 2, 3}},
		{name: "missing in the middle is pending", st: dbState{Tracker: Fence, Applied: set(1, 3)}, migs: migs(1, 2, 3),
			wantRecord: []int64{}, wantPending: []int64{2}},
		{name: "earlier tool state: files up to the version are recorded", st: dbState{Tracker: 3, Applied: set()}, migs: migs(1, 2, 3, 4),
			wantRecord: []int64{1, 2, 3}, wantPending: []int64{4}},
		{name: "earlier tool wrote the tracker after the takeover refuses", st: dbState{Tracker: 5, Applied: set(1, 3)}, migs: migs(1, 2, 3, 4, 5, 6),
			wantErr: &ErrTrackerMismatch{}},
		{name: "takeover with timestamp versions above the earlier tool's", st: dbState{Tracker: 3, Applied: set()}, migs: migs(1, 2, 3, 20261027000001),
			wantRecord: []int64{1, 2, 3}, wantPending: []int64{20261027000001}},
		{name: "takeover past timestamp versions is undecidable", st: dbState{Tracker: 20261027000002, Applied: set()}, migs: migs(1, 20261027000001, 20261027000002, 20261028000000),
			wantErr: &ErrUndecidedTakeover{}},
		{name: "fence without a recorded version: nothing applied", st: dbState{Tracker: Fence, Applied: set()}, migs: migs(1, 2),
			wantRecord: []int64{}, wantPending: []int64{1, 2}},
		{name: "dirty refuses", st: dbState{Tracker: 2, Dirty: true, Applied: set(1)}, migs: migs(1, 2, 3),
			wantErr: &ErrDirty{}},
		{name: "tracker below the recorded versions refuses", st: dbState{Tracker: 1, Applied: set(1, 3)}, migs: migs(1, 2, 3),
			wantErr: &ErrTrackerMismatch{}},
		{name: "applied above every shipped file refuses", st: dbState{Tracker: Fence, Applied: set(1, 9)}, migs: migs(1, 2, 3),
			wantErr: &ErrNewerDatabase{}},
		{name: "earlier tool version above every shipped file refuses", st: dbState{Tracker: 9, Applied: set()}, migs: migs(1, 2, 3),
			wantErr: &ErrNewerDatabase{}},
		{name: "unknown applied version below the newest is reported", st: dbState{Tracker: Fence, Applied: set(1, 2, 3)}, migs: migs(1, 3, 4),
			wantRecord: []int64{}, wantPending: []int64{4}, wantUnknown: []int64{2}},
		{name: "baseline on a fresh database", st: dbState{Applied: set()}, migs: baseline,
			wantRecord: []int64{}, wantPending: []int64{100, 110, 120}},
		{name: "earlier tool at the baseline", st: dbState{Tracker: 100, Applied: set()}, migs: baseline,
			wantRecord: []int64{100}, wantPending: []int64{110, 120}},
		{name: "older than the baseline refuses", st: dbState{Tracker: 50, Applied: set()}, migs: baseline,
			wantErr: &ErrOlderThanBaseline{}},
		{name: "recorded versions below the baseline are not unknown", st: dbState{Tracker: Fence, Applied: set(40, 50, 100, 110)}, migs: baseline,
			wantRecord: []int64{}, wantPending: []int64{120}},
		{name: "recorded history without the baseline refuses", st: dbState{Tracker: Fence, Applied: set(40, 50)}, migs: baseline,
			wantErr: &ErrOlderThanBaseline{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := resolve(tc.st, tc.migs)
			if tc.wantErr != nil {
				if err == nil || !errors.As(err, tc.wantErr) {
					t.Fatalf("err = %v, want %T", err, tc.wantErr)
				}
				if !IsRefusal(err) {
					t.Fatalf("IsRefusal(%v) = false", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := versionsOf(p.Record); !reflect.DeepEqual(got, tc.wantRecord) {
				t.Errorf("record = %v, want %v", got, tc.wantRecord)
			}
			if got := versionsOf(p.Pending); !reflect.DeepEqual(got, tc.wantPending) {
				t.Errorf("pending = %v, want %v", got, tc.wantPending)
			}
			if len(p.Unknown) > 0 || len(tc.wantUnknown) > 0 {
				if !reflect.DeepEqual(p.Unknown, tc.wantUnknown) {
					t.Errorf("unknown = %v, want %v", p.Unknown, tc.wantUnknown)
				}
			}
		})
	}
}

// The key must be the earlier tool's, so the two never migrate one
// database at once during an upgrade (values from its implementation).
func TestLockKeyMatchesTheEarlierTool(t *testing.T) {
	if got := LockKey("openctem", "public"); got != 215691687 {
		t.Errorf("LockKey(openctem, public) = %d", got)
	}
	if got := LockKey("lp_test", "app"); got != 795859944 {
		t.Errorf("LockKey(lp_test, app) = %d", got)
	}
}

func write(t *testing.T, dir, file, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "000002_b.up.sql", "")
	write(t, dir, "000002_b.down.sql", "")
	write(t, dir, "20261027101500_c.up.sql", "")
	write(t, dir, "000001_a.up.sql", "")
	write(t, dir, "README.md", "")
	if err := os.Mkdir(filepath.Join(dir, "seed"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := versionsOf(got); !reflect.DeepEqual(v, []int64{1, 2, 20261027101500}) {
		t.Fatalf("versions = %v", v)
	}
	if got[1].DownPath == "" || got[0].DownPath != "" || got[2].Stem() != "20261027101500_c" {
		t.Fatalf("paths = %+v", got)
	}
}

func TestLoadRefuses(t *testing.T) {
	cases := map[string][]string{
		"duplicate version":   {"000002_a.up.sql", "000002_b.up.sql"},
		"same number, widths": {"2_a.up.sql", "000002_b.up.sql"},
		"down without up":     {"000001_a.up.sql", "000002_b.down.sql"},
		"baseline not lowest": {"000001_a.up.sql", "000005_baseline.up.sql"},
		"zero version":        {"000000_a.up.sql"},
		"the fence version":   {"9223372036854775807_a.up.sql"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range files {
				write(t, dir, f, "")
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("Load accepted it")
			}
		})
	}
}

// The shipped tree must load: unique versions, every down with its up.
func TestLoadShippedMigrations(t *testing.T) {
	got, err := Load("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no migrations")
	}
}
