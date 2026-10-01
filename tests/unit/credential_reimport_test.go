package unit

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/credential"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Re-importing a leaked credential must update the stored one. The import
// looked it up by the credential fingerprint but stored it under the exposure
// event's own fingerprint, so the lookup never matched and every re-import
// failed with "exposure event already exists".

func importOnce(t *testing.T, svc interface {
	Import(context.Context, string, credential.ImportRequest) (*credential.ImportResult, error)
}, tenantID shared.ID, cred credential.CredentialImport) *credential.ImportResult {
	t.Helper()
	res, err := svc.Import(context.Background(), tenantID.String(), validImportRequest(cred))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("import errors: %+v", res.Errors)
	}
	return res
}

func TestCredentialReimport_UpdatesInsteadOfFailing(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	cred := validCredentialImport()

	first := importOnce(t, svc, tenantID, cred)
	if first.Imported != 1 {
		t.Fatalf("first import: imported=%d", first.Imported)
	}
	stored := repo.events[first.Details[0].ID]
	if got, want := stored.Fingerprint(), cred.CalculateFingerprint(tenantID.String()); got != want {
		t.Fatalf("stored under fingerprint %s, want the credential fingerprint %s", got, want)
	}
	seen := stored.LastSeenAt()
	time.Sleep(5 * time.Millisecond)

	second := importOnce(t, svc, tenantID, cred)
	if second.Imported != 0 || second.Updated != 1 {
		t.Fatalf("re-import: imported=%d updated=%d, want 0/1", second.Imported, second.Updated)
	}
	if second.Details[0].ID != first.Details[0].ID {
		t.Fatalf("re-import touched %s, want the stored %s", second.Details[0].ID, first.Details[0].ID)
	}
	if repo.createCalls != 1 || len(repo.events) != 1 {
		t.Fatalf("want one stored credential, got creates=%d rows=%d", repo.createCalls, len(repo.events))
	}
	if !repo.events[first.Details[0].ID].LastSeenAt().After(seen) {
		t.Fatal("re-import must move last_seen_at forward")
	}
}

// The credential fingerprint includes the breach; the event's did not, so the
// same address in a second breach was refused as a duplicate.
func TestCredentialReimport_SameIdentityOtherBreachIsSeparate(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	a := validCredentialImport()
	b := validCredentialImport()
	b.DedupKey.BreachName = "another_breach_2025"

	importOnce(t, svc, tenantID, a)
	res := importOnce(t, svc, tenantID, b)
	if res.Imported != 1 || len(repo.events) != 2 {
		t.Fatalf("second breach: imported=%d rows=%d, want 1/2", res.Imported, len(repo.events))
	}
}

// A row stored before the fix carries the event fingerprint. Re-importing the
// same credential adopts it (and re-keys it) instead of creating a duplicate.
func TestCredentialReimport_AdoptsRowStoredBeforeTheFix(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	cred := validCredentialImport()

	legacy, err := exposure.NewExposureEvent(tenantID, exposure.EventTypeCredentialLeaked, exposure.SeverityHigh,
		cred.Identifier, cred.GetSourceString(), cred.ToDetails())
	if err != nil {
		t.Fatal(err)
	}
	repo.addExistingEvent(legacy)

	res := importOnce(t, svc, tenantID, cred)
	if res.Imported != 0 || res.Updated != 1 || res.Details[0].ID != legacy.ID().String() {
		t.Fatalf("legacy row: imported=%d updated=%d id=%s, want it updated", res.Imported, res.Updated, res.Details[0].ID)
	}
	if got, want := repo.events[legacy.ID().String()].Fingerprint(), cred.CalculateFingerprint(tenantID.String()); got != want {
		t.Fatalf("legacy row not re-keyed: %s, want %s", got, want)
	}

	// A different breach that collides with the legacy row's coarse
	// fingerprint is still its own credential.
	other := validCredentialImport()
	other.DedupKey.BreachName = "another_breach_2025"
	res = importOnce(t, svc, tenantID, other)
	if res.Imported != 1 {
		t.Fatalf("other breach next to a legacy row: imported=%d, want 1", res.Imported)
	}
}
