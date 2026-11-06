package scmapp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeLifecycle struct {
	assets   map[string]shared.ID // tenant|host|repoID -> asset
	renamed  []string
	pipeName []string
	archived []string
	taken    bool
}

func (f *fakeLifecycle) FindRepositoryByProviderID(_ context.Context, t shared.ID, host, id string) (shared.ID, bool, error) {
	a, ok := f.assets[t.String()+"|"+host+"|"+id]
	return a, ok, nil
}
func (f *fakeLifecycle) RenameRepositoryAsset(_ context.Context, t, _ shared.ID, name string) (bool, error) {
	if f.taken {
		return false, nil
	}
	f.renamed = append(f.renamed, t.String()+"|"+name)
	return true, nil
}
func (f *fakeLifecycle) RenamePipelineRepository(_ context.Context, t shared.ID, _, _, id, name string) (int64, error) {
	f.pipeName = append(f.pipeName, t.String()+"|"+id+"|"+name)
	return 1, nil
}
func (f *fakeLifecycle) SetPipelinesRepositoryArchived(_ context.Context, t shared.ID, _, _, id string, a bool) (int64, error) {
	f.archived = append(f.archived, t.String()+"|"+id+"|"+map[bool]string{true: "archived", false: "unarchived"}[a])
	return 1, nil
}

func repoEventSetup() (*Service, *fakeLifecycle, *memAudit, shared.ID, shared.ID) {
	gh := &fakeGitHub{sigOK: true}
	tenant, other, asset := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &memRepo{rows: []scmapp.Installation{
		{ID: shared.NewID(), TenantID: tenant, Provider: "github", InstallationID: 11, AccountLogin: "acme", Status: "active"},
		{ID: shared.NewID(), TenantID: other, Provider: "github", InstallationID: 22, AccountLogin: "evil", Status: "active"},
		{ID: shared.NewID(), TenantID: tenant, Provider: "github", InstallationID: 33, AccountLogin: "gone", Status: "deleted"},
	}}
	audit := &memAudit{}
	svc := NewService(repo, gh, "s", audit, nil)
	lc := &fakeLifecycle{assets: map[string]shared.ID{tenant.String() + "|github.com|77": asset}}
	svc.SetRepositoryLifecycle(lc)
	return svc, lc, audit, tenant, other
}

const renameBody = `{"action":"renamed","repository":{"id":77,"full_name":"acme/new-name","html_url":"https://github.com/acme/new-name"},"installation":{"id":%d}}`

func send(t *testing.T, svc *Service, event, sig, body string) error {
	t.Helper()
	return svc.HandleGitHubWebhook(context.Background(), event, sig, []byte(body))
}

func TestRepositoryRenamedRenamesAssetAndPipelinesInTheInstallationsTenant(t *testing.T) {
	svc, lc, audit, tenant, _ := repoEventSetup()
	if err := send(t, svc, "repository", "good", fmt.Sprintf(renameBody, 11)); err != nil {
		t.Fatal(err)
	}
	if len(lc.renamed) != 1 || lc.renamed[0] != tenant.String()+"|github.com/acme/new-name" {
		t.Fatalf("asset renames = %v", lc.renamed)
	}
	if len(lc.pipeName) != 1 || len(audit.actions) != 1 {
		t.Fatalf("pipelines %v audit %v", lc.pipeName, audit.actions)
	}
}

func TestRepositoryEventsNeverCrossTenantsOrTrustUnsignedOrInactive(t *testing.T) {
	svc, lc, _, _, _ := repoEventSetup()
	// Unsigned: refused, nothing changes.
	if err := send(t, svc, "repository", "bad", fmt.Sprintf(renameBody, 11)); err == nil {
		t.Fatal("unsigned delivery accepted")
	}
	// The other tenant's installation names a repository id only the first
	// tenant has an asset for: the lookup is scoped to the caller's tenant.
	if err := send(t, svc, "repository", "good", fmt.Sprintf(renameBody, 22)); err != nil {
		t.Fatal(err)
	}
	if len(lc.renamed) != 0 {
		t.Fatalf("another tenant's asset was renamed: %v", lc.renamed)
	}
	// A deleted installation and an unknown one change nothing.
	_ = send(t, svc, "repository", "good", fmt.Sprintf(renameBody, 33))
	_ = send(t, svc, "repository", "good", fmt.Sprintf(renameBody, 99))
	if len(lc.pipeName) != 1 { // only the other tenant's own (empty) pipelines were asked
		t.Fatalf("pipeline updates = %v", lc.pipeName)
	}
}

func TestRepositoryRenameKeepsNameWhenTaken(t *testing.T) {
	svc, lc, audit, _, _ := repoEventSetup()
	lc.taken = true
	if err := send(t, svc, "repository", "good", fmt.Sprintf(renameBody, 11)); err != nil || len(audit.actions) != 0 {
		t.Fatalf("err=%v audit=%v", err, audit.actions)
	}
}

func TestRepositoryArchivedAndUnarchivedFlagPipelines(t *testing.T) {
	svc, lc, _, tenant, _ := repoEventSetup()
	body := `{"action":"archived","repository":{"id":77,"full_name":"acme/app","html_url":"https://github.com/acme/app"},"installation":{"id":11}}`
	if err := send(t, svc, "repository", "good", body); err != nil {
		t.Fatal(err)
	}
	if err := send(t, svc, "repository", "good", `{"action":"unarchived","repository":{"id":77},"installation":{"id":11}}`); err != nil {
		t.Fatal(err)
	}
	want := []string{tenant.String() + "|77|archived", tenant.String() + "|77|unarchived"}
	if len(lc.archived) != 2 || lc.archived[0] != want[0] || lc.archived[1] != want[1] {
		t.Fatalf("archived = %v", lc.archived)
	}
	// Other actions are ignored.
	if err := send(t, svc, "repository", "good", `{"action":"edited","repository":{"id":77},"installation":{"id":11}}`); err != nil || len(lc.archived) != 2 {
		t.Fatalf("edited: %v", err)
	}
}

func TestArchivedRepositoryPipelineIsArchivedNotStale(t *testing.T) {
	now := time.Now()
	ago := now.Add(-3 * 24 * time.Hour)
	p := cirun.Pipeline{LastRunAt: &ago, LastRunStatus: cirun.StatusEvaluated}
	if st := p.Assess(now, cirun.StatusPolicy{}).Status; st == cirun.PipelineArchived {
		t.Fatalf("precondition: status %s", st)
	}
	p.RepositoryArchivedAt = &now
	if st := p.Assess(now, cirun.StatusPolicy{}).Status; st != cirun.PipelineArchived {
		t.Fatalf("status = %s, want archived", st)
	}
}
