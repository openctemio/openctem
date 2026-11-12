package bountyprogram

import "testing"

func TestValidateSyncSource(t *testing.T) {
	prog := "https://www.acme.example/security"
	ok := []SyncSourceInput{
		{Source: ScopeSourcePaste},
		{Source: ScopeSourceFile, URL: "https://acme.example/scope.txt"},
		{Source: ScopeSourceFile, URL: "https://security.acme.example/bounty/scope.csv"},
		{Source: ScopeSourceAPI, Handle: "acme", Username: "jdoe", Token: "t"},
	}
	for i, in := range ok {
		if err := ValidateSyncSource(in, prog, false); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	bad := []SyncSourceInput{
		{Source: "ftp"},
		{Source: ScopeSourceFile, URL: "http://acme.example/scope.txt"},
		{Source: ScopeSourceFile, URL: "https://acme.example.evil.test/scope.txt"},
		{Source: ScopeSourceFile, URL: "https://user:pw@acme.example/scope.txt"},
		{Source: ScopeSourceFile, URL: "https://evil.example/scope.txt"},
		{Source: ScopeSourceAPI, Handle: "acme/../x", Username: "jdoe", Token: "t"},
		{Source: ScopeSourceAPI, Handle: "acme", Username: "", Token: "t"},
		{Source: ScopeSourceAPI, Handle: "acme", Username: "jdoe"},
		{Source: ScopeSourceAPI, Handle: "acme", Username: "jdoe", Token: "a\nb"},
	}
	for i, in := range bad {
		if err := ValidateSyncSource(in, prog, false); err == nil {
			t.Errorf("case %d must be refused: %+v", i, in)
		}
	}
	// A stored token may be kept.
	if err := ValidateSyncSource(SyncSourceInput{Source: ScopeSourceAPI, Handle: "acme", Username: "jdoe"}, prog, true); err != nil {
		t.Fatal(err)
	}
}

func TestDiffPlans(t *testing.T) {
	oldItems, _ := ParseScope("*.a.example\na.example\nb.example\n-x.a.example\n")
	newItems, _ := ParseScope("*.a.example\na.example\nc.example\n-y.a.example\n")
	d := DiffPlans(PlanScope(oldItems), PlanScope(newItems))
	if len(d.RemovedEntries) != 1 || d.RemovedEntries[0].Pattern != "b.example" {
		t.Errorf("removed: %+v", d.RemovedEntries)
	}
	if len(d.AddedEntries) != 1 || d.AddedEntries[0].Pattern != "c.example" {
		t.Errorf("added: %+v", d.AddedEntries)
	}
	if len(d.AddedExclusion) != 1 || d.AddedExclusion[0].Pattern != "y.a.example" {
		t.Errorf("added exclusions: %+v", d.AddedExclusion)
	}
	if len(d.RemovedExclusion) != 1 || d.RemovedExclusion[0].Pattern != "x.a.example" {
		t.Errorf("removed exclusions (widening): %+v", d.RemovedExclusion)
	}
	if !d.Narrows() || !d.Widens() {
		t.Error("both directions")
	}
	same := DiffPlans(PlanScope(oldItems), PlanScope(oldItems))
	if same.Narrows() || same.Widens() {
		t.Error("no change")
	}
}
