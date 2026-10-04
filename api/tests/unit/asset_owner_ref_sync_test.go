package unit

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One owner model: owner_ref is a hint, and the member it names becomes the
// asset's primary owner in asset_owners (SyncOwnerRefOwner). These tests pin
// when the asset service syncs it.

type ownerRefSyncCall struct {
	assetID shared.ID
	userID  *shared.ID
}

type ownerRefSyncRepo struct {
	mockAccessControlRepo
	calls []ownerRefSyncCall
}

func (m *ownerRefSyncRepo) SyncOwnerRefOwner(_ context.Context, _, assetID shared.ID, userID *shared.ID) error {
	m.calls = append(m.calls, ownerRefSyncCall{assetID: assetID, userID: userID})
	return nil
}

type emailMatcher struct{ byEmail map[string]shared.ID }

func (m emailMatcher) FindUserIDByEmail(_ context.Context, _ shared.ID, email string) (*shared.ID, error) {
	if id, ok := m.byEmail[strings.ToLower(email)]; ok {
		return &id, nil
	}
	return nil, nil
}

func newOwnerRefService(t *testing.T, byEmail map[string]shared.ID) (*app.AssetService, *ownerRefSyncRepo) {
	t.Helper()
	svc, _ := newTestService()
	repo := &ownerRefSyncRepo{}
	svc.SetAccessControlRepository(repo)
	svc.SetUserMatcher(emailMatcher{byEmail: byEmail})
	return svc, repo
}

func TestAssetOwnerRef_CreateSyncsMatchedMember(t *testing.T) {
	alice := shared.NewID()
	svc, repo := newOwnerRefService(t, map[string]shared.ID{"alice@example.test": alice})

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID: shared.NewID().String(), Name: "owner-ref-host", Type: "host", Criticality: "high",
		OwnerRef: "alice@example.test",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(repo.calls) != 1 || repo.calls[0].assetID != a.ID() || repo.calls[0].userID == nil || *repo.calls[0].userID != alice {
		t.Fatalf("sync calls = %+v, want one for the new asset naming alice", repo.calls)
	}
}

func TestAssetOwnerRef_CreateWithoutOwnerRefDoesNotSync(t *testing.T) {
	svc, repo := newOwnerRefService(t, nil)
	if _, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID: shared.NewID().String(), Name: "no-owner-ref", Type: "host", Criticality: "high",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(repo.calls) != 0 {
		t.Fatalf("sync calls = %+v, want none", repo.calls)
	}
}

// Changing owner_ref replaces the derived owner; clearing it (or a value that
// matches nobody) removes it; an update that leaves owner_ref alone does not
// touch owners.
func TestAssetOwnerRef_UpdateResyncsOnlyOnChange(t *testing.T) {
	alice, bob := shared.NewID(), shared.NewID()
	svc, repo := newOwnerRefService(t, map[string]shared.ID{"alice@example.test": alice, "bob@example.test": bob})
	tenant := shared.NewID().String()

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID: tenant, Name: "owner-ref-update", Type: "host", Criticality: "high", OwnerRef: "alice@example.test",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	repo.calls = nil

	update := func(in app.UpdateAssetInput) {
		t.Helper()
		if _, err := svc.UpdateAsset(context.Background(), a.ID().String(), tenant, in); err != nil {
			t.Fatalf("update: %v", err)
		}
	}

	desc := "unrelated edit"
	update(app.UpdateAssetInput{Description: &desc})
	same := "alice@example.test"
	update(app.UpdateAssetInput{OwnerRef: &same})
	if len(repo.calls) != 0 {
		t.Fatalf("unchanged owner_ref synced: %+v", repo.calls)
	}

	bobRef := "bob@example.test"
	update(app.UpdateAssetInput{OwnerRef: &bobRef})
	if len(repo.calls) != 1 || repo.calls[0].userID == nil || *repo.calls[0].userID != bob {
		t.Fatalf("after owner_ref → bob: %+v", repo.calls)
	}

	team := "platform-team"
	update(app.UpdateAssetInput{OwnerRef: &team})
	if len(repo.calls) != 2 || repo.calls[1].userID != nil {
		t.Fatalf("after owner_ref → a team name: %+v, want a sync with no user", repo.calls)
	}
}
