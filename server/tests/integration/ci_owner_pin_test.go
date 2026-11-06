package integration

import (
	"context"
	"net/http"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A trust configuration pins the namespace id that first used a name: a
// group renamed or deleted and registered again by someone else (same name,
// new id) is refused and audited; changing the configuration's owners drops
// the pins; another tenant pins on its own (RFC-077 G-10).
func TestCIOwnerIDPinning(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "6666666666666666666666666666666666666666"
	ns := func(id string) map[string]any { return map[string]any{"namespace_id": id} }

	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, ns("100"))); code != http.StatusCreated {
		t.Fatalf("first exchange: %d %v", code, out)
	}
	pins, err := r.svc.OwnerPins(ctx, r.tenant, cfg.ID)
	if err != nil || len(pins) != 1 || pins[0].OwnerName != "acme" || pins[0].OwnerID != "100" {
		t.Fatalf("pins = %+v %v", pins, err)
	}
	if r.auditCount(r.tenant, "ci_trust_config.updated", "owner_pinned") != 1 {
		t.Fatal("pin not audited")
	}
	// The same name with another id: refused, audited with the rule.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/web", "main", sha, ns("200"))); code != http.StatusUnauthorized {
		t.Fatalf("other namespace id: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", cirunapp.RefuseOwnerPin) != 1 {
		t.Fatal("pin refusal not audited")
	}
	// The pinned id keeps working.
	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/web", "main", sha, ns("100"))); code != http.StatusCreated {
		t.Fatalf("pinned id: %d %v", code, out)
	}
	// Another tenant trusting the same name pins its own.
	other := r.newTenant()
	ocfg := r.trust(other, cirun.Rules{Owners: []string{"acme"}})
	if code, out := r.exchange(other, r.idp.token(t, ocfg.Audience, "acme/api", "main", sha, ns("200"))); code != http.StatusCreated {
		t.Fatalf("other tenant: %d %v", code, out)
	}
	if pins, _ := r.svc.OwnerPins(ctx, r.tenant, cfg.ID); len(pins) != 1 || pins[0].OwnerID != "100" {
		t.Fatalf("other tenant changed this tenant's pin: %+v", pins)
	}
	// Changing the owners drops the pins; the next admitted id pins again.
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.TrustConfigInput{Name: cfg.Name, Issuer: cfg.Issuer,
		Audience: cfg.Audience, Rules: cirun.Rules{Owners: []string{"acme", "acme2"}}}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if pins, _ := r.svc.OwnerPins(ctx, r.tenant, cfg.ID); len(pins) != 0 {
		t.Fatalf("pins after owners changed: %+v", pins)
	}
	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, ns("200"))); code != http.StatusCreated {
		t.Fatalf("after re-pin: %d %v", code, out)
	}
}
