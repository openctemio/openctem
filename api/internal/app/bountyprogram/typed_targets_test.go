package bountyprogram

import (
	"context"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A program that lists services gets entries limited to their ports: the
// host itself is never in scope through them.
func TestImport_ServiceTargetsBecomePortLimitedEntries(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, user := shared.NewID(), shared.NewID()
	svc := NewService(repo, fullData(false), nil)
	in := Input{Name: "Svc", Platform: "self", ProgramURL: "https://svc.example/security", Visibility: "public",
		ScopeText: "In scope:\napi.svc.example:8443/tcp\n203.0.113.5:22\nOut of scope:\napi.svc.example:9000\n", Rules: bp.Rules{}}
	pv, err := svc.Preview(ctx, tenant, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := repo.Entries(ctx, tenant, p.ID)
	if len(entries) != 2 {
		t.Fatalf("entries: %d", len(entries))
	}
	for _, e := range entries {
		if e.Constraint().IsZero() || e.Matches(e.Pattern()) {
			t.Fatalf("%s: limit %+v; the bare host must not be covered", e.Pattern(), e.Constraint())
		}
	}
	// The out-of-scope service on another port is already outside the
	// limited entry; nothing excludes the in-scope port.
	excl, _ := repo.Exclusions(ctx, tenant, &p.ID)
	if len(excl) != 0 {
		t.Fatalf("exclusions: %+v", excl)
	}
	for _, e := range entries {
		if e.Pattern() == "api.svc.example" && (!e.Matches("api.svc.example:8443") || e.Matches("api.svc.example:9000")) {
			t.Fatalf("limit %+v", e.Constraint())
		}
	}
}
