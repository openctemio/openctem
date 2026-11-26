package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	assetapp "github.com/openctemio/openctem/server/internal/app/asset"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// Relationship writes are audited like the delete: the single create, the
// batch create (one entry per relationship it created) and an edit each
// leave an entry in the caller's tenant with the acting user and the stored
// "source -> type -> target" name; a create refused across tenants leaves
// none.
func TestAssetRelationshipWrites_AreAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	svc := assetapp.NewAssetRelationshipService(postgres.NewAssetRelationshipRepository(f.pg), postgres.NewAssetRepository(f.pg), logger.NewNop())
	h := NewAssetRelationshipHandler(svc, validator.New(), logger.NewNop())
	h.SetAuditService(f.auditSvc)
	src, dst := f.seedAsset(t, f.tenantA, "a.example.com"), f.seedAsset(t, f.tenantA, "b.example.com")
	more1, more2 := f.seedAsset(t, f.tenantA, "c.example.com"), f.seedAsset(t, f.tenantA, "d.example.com")
	body := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// Tenant B cannot link tenant A's assets, and nothing is recorded.
	rec := httptest.NewRecorder()
	h.Create(rec, f.req(http.MethodPost, "/x", f.tenantB,
		body(map[string]string{"type": "cname_of", "target_asset_id": dst}), "id", src))
	if rec.Code < 400 || f.total(t, auditdom.ActionAssetRelationshipCreated) != 0 {
		t.Fatalf("cross-tenant create: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionAssetRelationshipCreated))
	}

	rec = httptest.NewRecorder()
	h.Create(rec, f.req(http.MethodPost, "/x", f.tenantA,
		body(map[string]string{"type": "cname_of", "target_asset_id": dst}), "id", src))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("create response: %v %s", err, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionAssetRelationshipCreated, auditdom.ResourceTypeAssetRelationship, created.ID,
		"a.example.com -> cname_of -> b.example.com")

	rec = httptest.NewRecorder()
	h.Update(rec, f.req(http.MethodPut, "/x", f.tenantA, body(map[string]string{"description": "edited"}), "relationshipId", created.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionAssetRelationshipUpdated, auditdom.ResourceTypeAssetRelationship, created.ID,
		"a.example.com -> cname_of -> b.example.com")

	// The batch records one entry per relationship it created; the
	// duplicate of the first one records nothing.
	rec = httptest.NewRecorder()
	h.BatchCreate(rec, f.req(http.MethodPost, "/x", f.tenantA, body(map[string]any{"items": []map[string]string{
		{"type": "cname_of", "target_asset_id": dst},
		{"type": "cname_of", "target_asset_id": more1},
		{"type": "cname_of", "target_asset_id": more2},
	}}), "id", src))
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(f.entries(t, f.tenantA, auditdom.ActionAssetRelationshipCreated)); n != 3 {
		t.Errorf("created entries after the batch = %d, want 3 (1 single + 2 new in the batch)", n)
	}
	if n := len(f.entries(t, f.tenantB, auditdom.ActionAssetRelationshipCreated)); n != 0 {
		t.Errorf("%d created entries leaked into the other tenant", n)
	}
}

func TestRelationshipWriteActionsAreRegistered(t *testing.T) {
	for _, a := range []auditdom.Action{
		auditdom.ActionAssetRelationshipCreated, auditdom.ActionAssetRelationshipUpdated, auditdom.ActionAssetRelationshipApproved,
	} {
		if !a.IsValid() || a.Category() == "" {
			t.Errorf("%s: valid=%v category=%q", a, a.IsValid(), a.Category())
		}
	}
}
