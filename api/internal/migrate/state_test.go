package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

var defaultTakeover = Takeover{Releases: []Release{
	{Tags: []string{"v0.1.0"}, Versions: []int64{1, 2, 3}},
	{Tags: []string{"v0.2.0"}, Versions: []int64{1, 2, 3, 9}},
}}

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
		tk          *Takeover // nil: releases ending at 3 ({1, 2, 3}) and 9 ({1, 2, 3, 9})
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
		{name: "a file merged below the release's last one stays pending (003420 after v0.15.4)", st: dbState{Tracker: 4, Applied: set()}, migs: migs(1, 2, 3, 4, 5),
			tk: &Takeover{Releases: []Release{{Tags: []string{"v1"}, Versions: []int64{1, 2, 4}}}}, wantRecord: []int64{1, 2, 4}, wantPending: []int64{3, 5}},
		{name: "no release ends at the earlier tool's version refuses", st: dbState{Tracker: 2, Applied: set()}, migs: migs(1, 2, 3),
			wantErr: &ErrUndecidedTakeover{}},
		{name: "releases ending at one version with different files refuse", st: dbState{Tracker: 4, Applied: set()}, migs: migs(1, 2, 3, 4),
			tk: &Takeover{Releases: []Release{{Tags: []string{"v1"}, Versions: []int64{1, 2, 4}}, {Tags: []string{"v2"}, Versions: []int64{1, 3, 4}}}}, wantErr: &ErrUndecidedTakeover{}},
		{name: "releases ending at one version with the same files match", st: dbState{Tracker: 4, Applied: set()}, migs: migs(1, 2, 3, 4),
			tk: &Takeover{Releases: []Release{{Tags: []string{"v1"}, Versions: []int64{1, 2, 4}}, {Tags: []string{"v1.1"}, Versions: []int64{4, 2, 1}}}}, wantRecord: []int64{1, 2, 4}, wantPending: []int64{3}},
		{name: "an operator's list replaces the release match", st: dbState{Tracker: 20261027000002, Applied: set()}, migs: migs(1, 2, 20261027000001, 20261027000002, 20261028000000),
			tk: &Takeover{AssumeApplied: set(1, 2, 20261027000002)}, wantRecord: []int64{1, 2, 20261027000002}, wantPending: []int64{20261027000001, 20261028000000}},
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
			tk := defaultTakeover
			if tc.tk != nil {
				tk = *tc.tk
			}
			p, err := resolve(tc.st, tc.migs, tk)
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

// A dirty database the earlier tool left: which migrations below the failed
// one it applied is unknown, and the refusal says so.
func TestResolveDirtyEarlierTool(t *testing.T) {
	var d ErrDirty
	_, err := resolve(dbState{Tracker: 3, Dirty: true, Applied: set()}, migs(1, 2, 3), defaultTakeover)
	if !errors.As(err, &d) || !d.EarlierTool || !strings.Contains(err.Error(), "-assume-applied") {
		t.Fatalf("err = %v, want ErrDirty from the earlier tool", err)
	}
	// The runner's own dirty state (versions recorded).
	_, err = resolve(dbState{Tracker: 2, Dirty: true, Applied: set(1)}, migs(1, 2), defaultTakeover)
	if !errors.As(err, &d) || d.EarlierTool {
		t.Fatalf("err = %v, want the runner's own ErrDirty", err)
	}
}

func TestParseAssumeApplied(t *testing.T) {
	ms := migs(1, 3420, 20261027000001)
	got, err := ParseAssumeApplied(strings.NewReader("# applied on live\n000001\n\n003420_retest_seen.up.sql  # by hand\n"), ms)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, set(1, 3420)) {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"3421\n", "abc\n", "-1\n"} {
		if _, err := ParseAssumeApplied(strings.NewReader(bad), ms); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// The shipped released.json: v0.15.4 ends at 003428 and lacks 003420
// (merged to develop later), so a takeover of a v0.15.4 database leaves
// 003420 to run.
func TestShippedReleasedMigrations(t *testing.T) {
	rels, err := LoadReleases("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rels {
		for _, tag := range r.Tags {
			if tag != "v0.15.4" {
				continue
			}
			if r.highest() != 3428 {
				t.Fatalf("v0.15.4 ends at %d, want 3428", r.highest())
			}
			for _, v := range r.Versions {
				if v == 3420 {
					t.Fatal("v0.15.4 lists 003420, which it never shipped")
				}
			}
			return
		}
	}
	t.Fatal("released.json has no v0.15.4")
}

// A database a newer release migrated still gets its pending list: a
// migration this release ships that it lacks must not go unnoticed.
func TestResolveNewerDatabaseStillComputesPending(t *testing.T) {
	cases := []struct {
		name string
		st   dbState
		migs []Migration
		want []int64
	}{
		{"recorded versions above the shipped ones, one shipped missing", dbState{Tracker: Fence, Applied: set(1, 3, 9)}, migs(1, 2, 3), []int64{2}},
		{"recorded versions above the shipped ones, none missing", dbState{Tracker: Fence, Applied: set(1, 2, 3, 9)}, migs(1, 2, 3), []int64{}},
		{"earlier tool above the shipped ones", dbState{Tracker: 9, Applied: set()}, migs(1, 2, 3), []int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := resolve(tc.st, tc.migs, defaultTakeover)
			var n ErrNewerDatabase
			if !errors.As(err, &n) {
				t.Fatalf("err = %v, want ErrNewerDatabase", err)
			}
			if got := versionsOf(p.Pending); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("pending = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveReportsRenamedMigrations(t *testing.T) {
	st := dbState{Tracker: Fence, Applied: set(1, 2), Names: map[int64]string{1: "m", 2: "old_name"}}
	p, err := resolve(st, migs(1, 2, 3), defaultTakeover)
	if err != nil {
		t.Fatal(err)
	}
	want := []Renamed{{Version: 2, Applied: "old_name", Shipped: "m"}}
	if !reflect.DeepEqual(p.Renamed, want) {
		t.Fatalf("renamed = %+v, want %+v", p.Renamed, want)
	}
}
