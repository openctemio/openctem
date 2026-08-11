package exposurebridge_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/api/internal/app/exposurebridge"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// In-memory fake exposure.Repository (only the methods the bridge exercises are
// backed by real behavior; the rest satisfy the interface).
// =============================================================================

type fakeExposureRepo struct {
	byFingerprint map[string]*exposure.ExposureEvent
	byID          map[string]*exposure.ExposureEvent

	createCalls int
	updateCalls int
}

func newFakeExposureRepo() *fakeExposureRepo {
	return &fakeExposureRepo{
		byFingerprint: make(map[string]*exposure.ExposureEvent),
		byID:          make(map[string]*exposure.ExposureEvent),
	}
}

func (r *fakeExposureRepo) Create(_ context.Context, event *exposure.ExposureEvent) error {
	r.createCalls++
	if _, ok := r.byFingerprint[event.Fingerprint()]; ok {
		return exposure.NewExposureEventExistsError(event.Fingerprint())
	}
	r.byFingerprint[event.Fingerprint()] = event
	r.byID[event.ID().String()] = event
	return nil
}

func (r *fakeExposureRepo) CreateInTx(_ context.Context, _ *sql.Tx, event *exposure.ExposureEvent) error {
	return r.Create(context.Background(), event)
}

func (r *fakeExposureRepo) GetByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (*exposure.ExposureEvent, error) {
	if e, ok := r.byFingerprint[fingerprint]; ok {
		return e, nil
	}
	return nil, exposure.NewExposureEventNotFoundError(fingerprint)
}

func (r *fakeExposureRepo) Update(_ context.Context, event *exposure.ExposureEvent) error {
	r.updateCalls++
	r.byID[event.ID().String()] = event
	r.byFingerprint[event.Fingerprint()] = event
	return nil
}

func (r *fakeExposureRepo) GetByID(_ context.Context, id shared.ID) (*exposure.ExposureEvent, error) {
	if e, ok := r.byID[id.String()]; ok {
		return e, nil
	}
	return nil, exposure.NewExposureEventNotFoundError(id.String())
}

func (r *fakeExposureRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*exposure.ExposureEvent, error) {
	return r.GetByID(context.Background(), id)
}

func (r *fakeExposureRepo) Delete(_ context.Context, _ shared.ID) error { return nil }

func (r *fakeExposureRepo) List(_ context.Context, _ exposure.Filter, _ exposure.ListOptions, _ pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	return pagination.Result[*exposure.ExposureEvent]{}, nil
}
func (r *fakeExposureRepo) Count(_ context.Context, _ exposure.Filter) (int64, error) { return 0, nil }
func (r *fakeExposureRepo) ListByAsset(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	return pagination.Result[*exposure.ExposureEvent]{}, nil
}
func (r *fakeExposureRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (bool, error) {
	_, ok := r.byFingerprint[fingerprint]
	return ok, nil
}
func (r *fakeExposureRepo) Upsert(_ context.Context, _ *exposure.ExposureEvent) error { return nil }
func (r *fakeExposureRepo) BulkUpsert(_ context.Context, _ []*exposure.ExposureEvent) error {
	return nil
}
func (r *fakeExposureRepo) CountByState(_ context.Context, _ shared.ID) (map[exposure.State]int64, error) {
	return nil, nil
}
func (r *fakeExposureRepo) CountBySeverity(_ context.Context, _ shared.ID) (map[exposure.Severity]int64, error) {
	return nil, nil
}
func (r *fakeExposureRepo) MeanTimeToResolveHours(_ context.Context, _ shared.ID) (float64, bool, error) {
	return 0, false, nil
}

// =============================================================================
// Helpers
// =============================================================================

func testLogger() *logger.Logger {
	return logger.NewNop()
}

func newSecretFinding(t *testing.T, tenantID, assetID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSecret,
		"gitleaks",
		vulnerability.SeverityHigh,
		"hardcoded AWS key",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetFindingType(vulnerability.FindingTypeSecret)
	f.SetTitle("aws-access-token")
	f.SetRuleID("aws-access-token")
	f.SetFingerprint("fp-secret-1")
	f.SetSecretType("aws-access-token")
	f.SetSecretService("aws")
	f.SetSecretMaskedValue("AKIA****WXYZ")
	f.SetLocation("config/prod.env", 12, 12, 1, 40)
	return f
}

// =============================================================================
// Tests
// =============================================================================

func TestBridge_CreatesLabeledExposureForSecretFinding(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	assetID := shared.NewID()
	f := newSecretFinding(t, tenantID, assetID)

	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f}); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create, got %d", repo.createCalls)
	}
	if len(repo.byID) != 1 {
		t.Fatalf("expected 1 exposure event, got %d", len(repo.byID))
	}

	var event *exposure.ExposureEvent
	for _, e := range repo.byID {
		event = e
	}

	if event.EventType() != exposure.EventTypeCredentialLeaked {
		t.Errorf("event_type = %q, want credential_leaked", event.EventType())
	}
	// Provenance: labeled as an internal secret-scan discovery, NOT a breach import.
	if event.Source() != exposurebridge.SourceSecretScan {
		t.Errorf("source = %q, want %q", event.Source(), exposurebridge.SourceSecretScan)
	}
	details := event.Details()
	if got := details["discovery_source"]; got != exposurebridge.SourceSecretScan {
		t.Errorf("discovery_source = %v, want %q", got, exposurebridge.SourceSecretScan)
	}
	// Linked back to the source finding + asset.
	if got := details["finding_id"]; got != f.ID().String() {
		t.Errorf("finding_id = %v, want %s", got, f.ID().String())
	}
	if event.AssetID() == nil || event.AssetID().String() != assetID.String() {
		t.Errorf("asset link = %v, want %s", event.AssetID(), assetID.String())
	}
	// Severity carried across.
	if event.Severity() != exposure.SeverityHigh {
		t.Errorf("severity = %q, want high", event.Severity())
	}
}

func TestBridge_SecretValueStaysMasked(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	f := newSecretFinding(t, tenantID, shared.NewID())

	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f}); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	var event *exposure.ExposureEvent
	for _, e := range repo.byID {
		event = e
	}
	masked := event.Details()["masked_value"]
	if masked != "AKIA****WXYZ" {
		t.Errorf("masked_value = %v, want the finding's masked value", masked)
	}
	// The bridge only ever reads SecretMaskedValue; no raw-value key should exist.
	if _, ok := event.Details()["secret_value"]; ok {
		t.Error("exposure event must not carry a raw secret_value")
	}
}

func TestBridge_ReIngestDedupes(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	assetID := shared.NewID()

	// First scan.
	f1 := newSecretFinding(t, tenantID, assetID)
	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f1}); err != nil {
		t.Fatalf("ApplyBatch #1: %v", err)
	}

	// Re-scan: same secret, same asset — a new finding row (different ID) but
	// identical dedupe inputs (title/source/asset/service/path).
	f2 := newSecretFinding(t, tenantID, assetID)
	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f2}); err != nil {
		t.Fatalf("ApplyBatch #2: %v", err)
	}

	if repo.createCalls != 1 {
		t.Errorf("expected exactly 1 create across re-ingest, got %d", repo.createCalls)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 update (mark-seen) on re-ingest, got %d", repo.updateCalls)
	}
	if len(repo.byID) != 1 {
		t.Errorf("expected 1 exposure event after re-ingest, got %d", len(repo.byID))
	}
}

func TestBridge_NonSecretFindingIgnored(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	f, err := vulnerability.NewFinding(
		tenantID,
		shared.NewID(),
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"sql injection",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetFindingType(vulnerability.FindingTypeVulnerability)

	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f}); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	if repo.createCalls != 0 || len(repo.byID) != 0 {
		t.Errorf("non-secret finding must not create an exposure event (creates=%d, events=%d)", repo.createCalls, len(repo.byID))
	}
}

func TestBridge_ReactivatesResolvedOnRescan(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	assetID := shared.NewID()

	f := newSecretFinding(t, tenantID, assetID)
	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f}); err != nil {
		t.Fatalf("ApplyBatch #1: %v", err)
	}

	// User resolves the exposure.
	var event *exposure.ExposureEvent
	for _, e := range repo.byID {
		event = e
	}
	if err := event.Resolve(shared.NewID(), "rotated the key"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := repo.Update(context.Background(), event); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Re-scan finds the same secret still present → reactivate.
	f2 := newSecretFinding(t, tenantID, assetID)
	if err := bridge.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f2}); err != nil {
		t.Fatalf("ApplyBatch #2: %v", err)
	}

	if event.State() != exposure.StateActive {
		t.Errorf("state = %q, want active after re-scan reactivation", event.State())
	}
	if repo.createCalls != 1 {
		t.Errorf("expected no new create on reactivation, got %d creates", repo.createCalls)
	}
}
