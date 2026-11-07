package webendpoint

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDerivedCandidates_Rules(t *testing.T) {
	now := time.Now()
	in := DerivedInput{
		Own: []DerivedRow{
			{Template: "/index.php", LastSeen: now.Add(-time.Hour)},
			{Template: "/config.yml", Catalog: true, LastSeen: now.Add(-48 * time.Hour)},
			{Template: "/api/v3/users"},
			{Template: "/users/{int}/avatar.png"}, // templated: no mutation
			{Template: "/logout.php"},             // destructive: every mutation dropped
			{Template: "/admin/settings.php"},     // under the exclusion
			{Template: "/site.zip"},               // already a backup name
			{Template: "/index.php.bak"},          // known: never planned again
		},
		Siblings:  []SiblingPath{{Template: "/actuator/health", Origins: 3}, {Template: "/once", Origins: 1}, {Template: "/{id}/x", Origins: 4}},
		SpecPaths: []string{"/api/internal/report", "/api/delete-all"},
	}
	got := DerivedCandidates(in, []string{"/Admin"}, 0)
	has := func(p string) bool { return slices.Contains(got.Paths, p) }

	for _, want := range []string{"/config.yml.bak", "/index.php~", "/index.php.old", "/api/v1/users", "/api/v2/users",
		"/api/v4/users", "/actuator/health", "/api/internal/report"} {
		if !has(want) {
			t.Errorf("missing %s in %v", want, got.Paths)
		}
	}
	for _, never := range []string{"/index.php.bak", "/api/v3/users", "/once", "/{id}/x", "/api/delete-all",
		"/admin/settings.php.bak", "/site.zip.bak"} {
		if has(never) {
			t.Errorf("%s must not be planned", never)
		}
	}
	for _, p := range got.Paths {
		if strings.Contains(p, "{") || strings.Contains(strings.ToLower(p), "logout") {
			t.Errorf("templated or destructive candidate %s", p)
		}
	}
	// At most 8 suffixes per file; the sensitive file ranks first.
	n := 0
	for _, p := range got.Paths {
		if strings.HasPrefix(p, "/config.yml") {
			n++
		}
	}
	if n != MaxBackupMutationsPerFile {
		t.Errorf("config.yml has %d mutations, want %d", n, MaxBackupMutationsPerFile)
	}
	if got.Paths[0] != "/config.yml.bak" {
		t.Errorf("first candidate %s, want the sensitive file's backup", got.Paths[0])
	}
	if got.Truncated {
		t.Error("no limit, nothing truncated")
	}
}

// SECURITY: every spelling of an excluded path is dropped with the
// sensor's reading, read_only included (the caller passes every non-allowed
// exclusion as a deny path).
func TestDerivedCandidates_ExclusionSpellings(t *testing.T) {
	in := DerivedInput{SpecPaths: []string{"/Admin", "/%61dmin", "/x/../admin", "/admin;x", "/admin/panel", "/ok"}}
	got := DerivedCandidates(in, []string{"/admin"}, 0)
	if !slices.Equal(got.Paths, []string{"/ok"}) {
		t.Fatalf("planned %v, want only /ok", got.Paths)
	}
}

func TestDerivedCandidates_LimitInterleavesAndRecordsTruncation(t *testing.T) {
	in := DerivedInput{
		Own:      []DerivedRow{{Template: "/a.php"}, {Template: "/b.php"}, {Template: "/api/v2/x"}},
		Siblings: []SiblingPath{{Template: "/s1", Origins: 2}, {Template: "/s2", Origins: 5}},
	}
	got := DerivedCandidates(in, nil, 4)
	if !got.Truncated || len(got.Paths) != 4 {
		t.Fatalf("got %v truncated %v", got.Paths, got.Truncated)
	}
	if !slices.Contains(got.Paths, "/api/v1/x") || !slices.Contains(got.Paths, "/s2") {
		t.Fatalf("each class keeps a share of a short list: %v", got.Paths)
	}
}
