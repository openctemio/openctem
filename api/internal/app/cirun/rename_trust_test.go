package cirun

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type renameIdentity struct{ assetID shared.ID }

func (r renameIdentity) FindRepositoryByProviderID(context.Context, shared.ID, string, string) (shared.ID, bool, error) {
	return shared.ID{}, false, nil
}
func (r renameIdentity) StampRepositoryIdentity(context.Context, shared.ID, shared.ID, string, string, string) error {
	return nil
}
func (r renameIdentity) RenameRepositoryAsset(context.Context, shared.ID, shared.ID, string) (bool, error) {
	return false, nil
}
func (r renameIdentity) RepositoryAssetOfPipelineRepo(_ context.Context, _ shared.ID, _, _, repoID string) (shared.ID, bool, error) {
	if repoID == "123" && !r.assetID.IsZero() {
		return r.assetID, true, nil
	}
	return shared.ID{}, false, nil
}

type renameAssets struct{ a *asset.Asset }

func (r renameAssets) GetByID(context.Context, shared.ID, shared.ID) (*asset.Asset, error) {
	return r.a, nil
}
func (r renameAssets) GetByName(context.Context, shared.ID, string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (r renameAssets) Create(context.Context, *asset.Asset) error { return nil }

type captureAlerts struct{ got []AdminAlert }

func (c *captureAlerts) AlertAdmins(_ context.Context, _ shared.ID, a AdminAlert) { c.got = append(c.got, a) }

func renameService(t *testing.T, oldName string, known bool) (*Service, *captureAlerts, shared.ID) {
	t.Helper()
	tenant := shared.NewID()
	a, err := asset.NewAssetWithTenant(tenant, oldName, asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	id := shared.ID{}
	if known {
		id = a.ID()
	}
	al := &captureAlerts{}
	s := &Service{identity: renameIdentity{assetID: id}, assets: renameAssets{a: a}, alerts: al,
		cfg: Config{WebBaseURL: "https://app.example.com/"}, now: time.Now}
	s.log = logger.NewNop()
	return s, al, tenant
}

func renamedClaims(repo string) cirun.Claims {
	return cirun.Claims{Provider: cirun.ProviderGitHub, RepositoryID: "123", Repository: repo, Workflow: "ci"}
}

func trustConfigs(names ...string) []cirun.TrustConfig {
	var out []cirun.TrustConfig
	for _, n := range names {
		out = append(out, cirun.TrustConfig{ID: shared.NewID(), Name: n, Provider: cirun.ProviderGitHub, Issuer: "https://token.actions.githubusercontent.com"})
	}
	return out
}

const ghIssuer = "https://token.actions.githubusercontent.com/"

func TestRenamedRepositoryAlertsAdminsOnceWithTrustLink(t *testing.T) {
	s, al, tenant := renameService(t, "github.com/acme/old-name", true)
	cfgs := trustConfigs("acme repos")
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/new-name"), cfgs)
	if len(al.got) != 1 {
		t.Fatalf("alerts = %d, want 1", len(al.got))
	}
	a := al.got[0]
	if !a.Email || a.URL != "/ci-cd?tab=setup" || a.EmailLink != "https://app.example.com/ci-cd?tab=setup" {
		t.Fatalf("alert must be in-app + email with the trust settings link: %+v", a)
	}
	if !strings.Contains(a.Body, "old-name") || !strings.Contains(a.Body, "new-name") || !strings.Contains(a.Body, `"acme repos"`) {
		t.Fatalf("body = %q", a.Body)
	}
	if a.AggregateID == nil || *a.AggregateID != cfgs[0].ID {
		t.Fatal("a single matching configuration must be linked by id")
	}
	// The pipeline retries on every job: no second alert for the same rename.
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/new-name"), cfgs)
	if len(al.got) != 1 {
		t.Fatalf("alerted again for the same rename: %d", len(al.got))
	}
	// Another name is another event; another tenant is never deduped with this one.
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/newer-name"), cfgs)
	s.noteRenamedRepository(context.Background(), shared.NewID(), ghIssuer, renamedClaims("acme/new-name"), cfgs)
	if len(al.got) != 3 {
		t.Fatalf("alerts = %d, want 3", len(al.got))
	}
}

func TestRenamedRepositoryNoAlertWhenNothingWasRenamed(t *testing.T) {
	// A repository id never seen here: a missing configuration, not a rename.
	s, al, tenant := renameService(t, "github.com/acme/old-name", false)
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/new-name"), trustConfigs("c"))
	if len(al.got) != 0 {
		t.Fatalf("alerted for an unknown repository: %+v", al.got)
	}
	// Same name: refused for another reason.
	s, al, tenant = renameService(t, "github.com/acme/same", true)
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/same"), trustConfigs("c"))
	if len(al.got) != 0 {
		t.Fatalf("alerted without a rename: %+v", al.got)
	}
}

func TestRenamedRepositoryAlertTextIsSanitized(t *testing.T) {
	s, al, tenant := renameService(t, "github.com/acme/old", true)
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/new\nINJECTED\x00"), trustConfigs("a\nb"))
	if len(al.got) != 1 || strings.ContainsAny(al.got[0].Body, "\n\x00") || strings.ContainsAny(al.got[0].Title, "\n\x00") {
		t.Fatalf("unsanitized alert: %+v", al.got)
	}
}
