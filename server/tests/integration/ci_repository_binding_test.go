package integration

import (
	"context"
	"net/http"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A repository name stays with the repository id that first reported under
// it: trust rules match names, and a name can change hands (a group deleted
// and registered again, a project deleted and created anew). Another id
// under the same name is refused and audited until the old pipeline is
// retired; a rename (same id, new name) keeps working; another tenant is
// unaffected (RFC-051 section 8).
func TestCIRepositoryNameBoundToRepositoryID(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "4444444444444444444444444444444444444444"

	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil)); code != http.StatusCreated {
		t.Fatalf("first exchange: %d %v", code, out)
	}
	// Same name, another project id: refused, audited with the rule.
	impostor := map[string]any{"project_id": "8"}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, impostor)); code != http.StatusUnauthorized {
		t.Fatalf("another project under the same name: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", cirunapp.RefuseRepositoryBinding) != 1 {
		t.Fatal("binding refusal not audited")
	}
	// Same id under a new name (a rename): admitted.
	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api-v2", "main", sha, nil)); code != http.StatusCreated {
		t.Fatalf("rename: %d %v", code, out)
	}
	// Another tenant trusting the same group binds on its own.
	other := r.newTenant()
	ocfg := r.trust(other, cirun.Rules{Owners: []string{"acme"}})
	if code, out := r.exchange(other, r.idp.token(t, ocfg.Audience, "acme/web", "main", sha, impostor)); code != http.StatusCreated {
		t.Fatalf("other tenant: %d %v", code, out)
	}
	// The rename freed the old name; a new project there is admitted.
	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, impostor)); code != http.StatusCreated {
		t.Fatalf("new project on a freed name: %d %v", code, out)
	}
	// Retiring the pipeline that holds a name frees it too.
	pid := ""
	for _, p := range r.pipelines(r.tenant) {
		if p.ExternalRepoID == "8" {
			pid = p.ID.String()
		}
	}
	if pid == "" {
		t.Fatal("pipeline of project 8 not found")
	}
	third := map[string]any{"project_id": "9"}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, third)); code != http.StatusUnauthorized {
		t.Fatalf("third project before retiring: %d", code)
	}
	id, err := shared.IDFromString(pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.svc.RetirePipeline(ctx, r.tenant, id, "project deleted and recreated", cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if code, out := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, third)); code != http.StatusCreated {
		t.Fatalf("after retiring: %d %v", code, out)
	}
}
