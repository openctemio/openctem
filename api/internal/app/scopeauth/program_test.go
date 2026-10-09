package scopeauth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// programSources adds program exclusions to fakeSources.
type programSources struct {
	*fakeSources
	excl []bountyprogram.Exclusion
	err  error
}

func (p *programSources) ListProgramExclusions(_ context.Context, t shared.ID) ([]bountyprogram.Exclusion, error) {
	if p.err != nil {
		return nil, p.err
	}
	if !t.Equals(p.tenant) {
		return nil, nil
	}
	return p.excl, nil
}

func programEntry(t *testing.T, tenant shared.ID, pattern string) *scopedom.Target {
	t.Helper()
	e, err := scopedom.NewTarget(tenant, scopedom.TargetTypeDomain, pattern, "", "")
	if err != nil {
		t.Fatal(err)
	}
	pid := shared.NewID()
	if err := e.SetAuthorization(scopedom.AuthProgram, &pid); err != nil {
		t.Fatal(err)
	}
	return e
}

// Program exclusions bind program entries only (RFC-065 B7); a target only
// program entries cover is program-only (never platform sensors, §8).
func TestProgramEntriesAndExclusions(t *testing.T) {
	f := newSources(t) // *.scoped.com is an ownership entry
	f.targets = append(f.targets,
		programEntry(t, f.tenant, "*.acme.example"),
		programEntry(t, f.tenant, "*.scoped.com"), // overlaps ownership
	)
	p := &programSources{fakeSources: f, excl: []bountyprogram.Exclusion{
		{TenantID: f.tenant, TargetType: scopedom.TargetTypeDomain, Pattern: "admin.acme.example"},
		{TenantID: f.tenant, TargetType: scopedom.TargetTypeDomain, Pattern: "acme.example"},
		{TenantID: f.tenant, TargetType: scopedom.TargetTypeDomain, Pattern: "*.internal.scoped.com"},
	}}
	a, err := Load(context.Background(), f.tenant, p, f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target      string
		covered     bool
		programOnly bool
	}{
		{"www.acme.example", true, true},
		{"https://shop.acme.example/x", true, true},
		{"admin.acme.example", false, false}, // out of scope for the program
		{"acme.example", false, false},       // unlisted apex
		{"x.admin.acme.example", true, true}, // only the exact name was excluded
		// The program excludes it, the organization's own entry still covers it.
		{"a.internal.scoped.com", true, false},
		{"www.scoped.com", true, false},
		{"other.example", false, false},
	}
	for _, c := range cases {
		_, got := a.Covers(c.target)
		if got != c.covered {
			t.Errorf("%s: covered=%v, want %v", c.target, got, c.covered)
		}
		if po := a.ProgramOnly(c.target); po != c.programOnly {
			t.Errorf("%s: programOnly=%v, want %v", c.target, po, c.programOnly)
		}
		if _, got := a.CoversAt(c.target, scopedom.TierActive); got != c.covered {
			t.Errorf("%s: CoversAt t1=%v", c.target, got)
		}
	}
	if c := a.Ceiling("admin.acme.example"); c != nil {
		t.Errorf("an excluded name has no ceiling: %s", c.Pattern())
	}
}

// Without the program exclusions, program entries cover nothing (fail
// closed); ownership entries are unaffected. A read error refuses.
func TestProgramEntries_FailClosed(t *testing.T) {
	f := newSources(t)
	f.targets = append(f.targets, programEntry(t, f.tenant, "*.acme.example"))

	a, err := Load(context.Background(), f.tenant, f, f) // f has no ListProgramExclusions
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Covers("www.acme.example"); ok {
		t.Error("program entries must cover nothing without the exclusions")
	}
	if _, ok := a.Covers("www.scoped.com"); !ok {
		t.Error("ownership entries still cover")
	}

	notWired := &programSources{fakeSources: f, err: ErrProgramsNotWired}
	a, err = Load(context.Background(), f.tenant, notWired, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Covers("www.acme.example"); ok {
		t.Error("not wired: program entries cover nothing")
	}

	broken := &programSources{fakeSources: f, err: errors.New("db down")}
	if _, err := Load(context.Background(), f.tenant, broken, f); err == nil {
		t.Error("a failed read must refuse")
	}
}

// Another tenant's program exclusions never apply.
func TestProgramExclusions_TenantScoped(t *testing.T) {
	f := newSources(t)
	f.targets = append(f.targets, programEntry(t, f.tenant, "*.acme.example"))
	p := &programSources{fakeSources: f}
	a, err := Load(context.Background(), f.tenant, p, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Covers("admin.acme.example"); !ok {
		t.Error("no exclusion of this tenant: covered")
	}
}
