package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// An exception to the government and military rule
// (docs/rfcs/RFC-154-blocked-target-names.md) lets its organization add the
// name through every add path (single, preview, bulk), and nobody else; an
// expired one is refused; the refusal tells the tenant who can help and
// names no other organization.
func TestScopeEntry_GovernmentNameException(t *testing.T) {
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	now := time.Now()
	policy := scopedom.NewNamePolicy()
	policy.SetClock(func() time.Time { return now })
	policy.Set(scopedom.NameSnapshot{Exceptions: []scopedom.NameException{
		{TenantID: a, Name: "sub.example.gov.vn", ExpiresAt: now.Add(time.Hour)},
		{TenantID: a, Name: "old.example.gov.vn", ExpiresAt: now.Add(-time.Minute)},
	}})
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	svc.SetGovernance(fixedMode{scangov.ModeOff})
	svc.SetGuardrails(scopedom.DefaultGuardrails().WithNamePolicy(policy))

	if _, err := create(svc, a, approverA, "sub.example.gov.vn", nil); err != nil {
		t.Fatalf("organization A with an exception: %v", err)
	}
	for _, c := range []struct {
		tid     shared.ID
		pattern string
	}{
		{b, "sub.example.gov.vn"},   // another organization
		{a, "example.gov.vn"},       // the parent
		{a, "x.sub.example.gov.vn"}, // a child of an exact exception
		{a, "*.sub.example.gov.vn"}, // a wildcard over an exact exception
		{a, "old.example.gov.vn"},   // expired
	} {
		_, err := create(svc, c.tid, approverA, c.pattern, nil)
		if !errors.Is(err, scopedom.ErrGovernmentName) {
			t.Errorf("%s for %s: %v, want GOVERNMENT_NAME", c.pattern, c.tid, err)
			continue
		}
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Message != "government and military domains are blocked on this installation; your platform administrator can grant an exception" {
			t.Errorf("refusal text: %v", err)
		}
		in := scope.CreateTargetInput{TenantID: c.tid.String(), TargetType: "domain", Pattern: c.pattern, Actor: approverA}
		if _, err := svc.PreviewTarget(ctx, in); !errors.Is(err, scopedom.ErrGovernmentName) {
			t.Errorf("preview %s: %v", c.pattern, err)
		}
	}

	// Bulk add: the same answer per item.
	out, err := svc.CreateTargets(ctx, bulkIn(b, approverA, bulkItems("sub.example.gov.vn", "ok.bulk.example")))
	if err != nil {
		t.Fatal(err)
	}
	if domainCode(out[0].Err) != "GOVERNMENT_NAME" || out[1].Err != nil {
		t.Fatalf("bulk for B: %v / %v", out[0].Err, out[1].Err)
	}
	// The exception is gone at its expiry, with no refresh.
	now = now.Add(2 * time.Hour)
	if _, err := create(svc, a, approverA, "sub.example.gov.vn", func(in *scope.CreateTargetInput) { in.TargetType = "host" }); !errors.Is(err, scopedom.ErrGovernmentName) {
		t.Fatalf("after expiry: %v", err)
	}
}
