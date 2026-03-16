package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatintel"
	"github.com/openctemio/api/pkg/logger"
)

// ============================================================================
// Mock Repositories
// ============================================================================

type threatIntelMockEPSSRepo struct {
	scores       map[string]*threatintel.EPSSScore
	highRiskFn   func(ctx context.Context, threshold float64, limit int) ([]*threatintel.EPSSScore, error)
	countVal     int64
	countErr     error
	upsertErr    error
	getByIDErr   error
	getByIDsErr  error
	highRiskErr  error
}

func newThreatIntelMockEPSSRepo() *threatIntelMockEPSSRepo {
	return &threatIntelMockEPSSRepo{
		scores: make(map[string]*threatintel.EPSSScore),
	}
}

func (m *threatIntelMockEPSSRepo) Upsert(_ context.Context, score *threatintel.EPSSScore) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.scores[score.CVEID()] = score
	return nil
}

func (m *threatIntelMockEPSSRepo) UpsertBatch(_ context.Context, scores []*threatintel.EPSSScore) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	for _, s := range scores {
		m.scores[s.CVEID()] = s
	}
	return nil
}

func (m *threatIntelMockEPSSRepo) GetByCVEID(_ context.Context, cveID string) (*threatintel.EPSSScore, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	s, ok := m.scores[cveID]
	if !ok {
		return nil, threatintel.ErrEPSSNotFound
	}
	return s, nil
}

func (m *threatIntelMockEPSSRepo) GetByCVEIDs(_ context.Context, cveIDs []string) ([]*threatintel.EPSSScore, error) {
	if m.getByIDsErr != nil {
		return nil, m.getByIDsErr
	}
	result := make([]*threatintel.EPSSScore, 0, len(cveIDs))
	for _, id := range cveIDs {
		if s, ok := m.scores[id]; ok {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *threatIntelMockEPSSRepo) GetHighRisk(ctx context.Context, threshold float64, limit int) ([]*threatintel.EPSSScore, error) {
	if m.highRiskFn != nil {
		return m.highRiskFn(ctx, threshold, limit)
	}
	if m.highRiskErr != nil {
		return nil, m.highRiskErr
	}
	result := make([]*threatintel.EPSSScore, 0)
	for _, s := range m.scores {
		if s.Score() > threshold {
			result = append(result, s)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (m *threatIntelMockEPSSRepo) GetTopPercentile(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
	return nil, nil
}

func (m *threatIntelMockEPSSRepo) Count(_ context.Context) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.countVal > 0 {
		return m.countVal, nil
	}
	return int64(len(m.scores)), nil
}

func (m *threatIntelMockEPSSRepo) DeleteAll(_ context.Context) error {
	m.scores = make(map[string]*threatintel.EPSSScore)
	return nil
}

// ============================================================================

type threatIntelMockKEVRepo struct {
	entries          map[string]*threatintel.KEVEntry
	countVal         int64
	countErr         error
	upsertErr        error
	getByIDErr       error
	existsVal        bool
	existsErr        error
	pastDueEntries   []*threatintel.KEVEntry
	pastDueErr       error
	recentEntries    []*threatintel.KEVEntry
	recentErr        error
	ransomEntries    []*threatintel.KEVEntry
	ransomErr        error
}

func newThreatIntelMockKEVRepo() *threatIntelMockKEVRepo {
	return &threatIntelMockKEVRepo{
		entries: make(map[string]*threatintel.KEVEntry),
	}
}

func (m *threatIntelMockKEVRepo) Upsert(_ context.Context, entry *threatintel.KEVEntry) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.entries[entry.CVEID()] = entry
	return nil
}

func (m *threatIntelMockKEVRepo) UpsertBatch(_ context.Context, entries []*threatintel.KEVEntry) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	for _, e := range entries {
		m.entries[e.CVEID()] = e
	}
	return nil
}

func (m *threatIntelMockKEVRepo) GetByCVEID(_ context.Context, cveID string) (*threatintel.KEVEntry, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	e, ok := m.entries[cveID]
	if !ok {
		return nil, threatintel.ErrKEVNotFound
	}
	return e, nil
}

func (m *threatIntelMockKEVRepo) GetByCVEIDs(_ context.Context, cveIDs []string) ([]*threatintel.KEVEntry, error) {
	result := make([]*threatintel.KEVEntry, 0, len(cveIDs))
	for _, id := range cveIDs {
		if e, ok := m.entries[id]; ok {
			result = append(result, e)
		}
	}
	return result, nil
}

func (m *threatIntelMockKEVRepo) ExistsByCVEID(_ context.Context, cveID string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	if m.existsVal {
		return true, nil
	}
	_, ok := m.entries[cveID]
	return ok, nil
}

func (m *threatIntelMockKEVRepo) ExistsByCVEIDs(_ context.Context, cveIDs []string) (map[string]bool, error) {
	result := make(map[string]bool, len(cveIDs))
	for _, id := range cveIDs {
		_, ok := m.entries[id]
		result[id] = ok
	}
	return result, nil
}

func (m *threatIntelMockKEVRepo) GetPastDue(_ context.Context, _ int) ([]*threatintel.KEVEntry, error) {
	if m.pastDueErr != nil {
		return nil, m.pastDueErr
	}
	return m.pastDueEntries, nil
}

func (m *threatIntelMockKEVRepo) GetRecentlyAdded(_ context.Context, _, _ int) ([]*threatintel.KEVEntry, error) {
	if m.recentErr != nil {
		return nil, m.recentErr
	}
	return m.recentEntries, nil
}

func (m *threatIntelMockKEVRepo) GetRansomwareRelated(_ context.Context, _ int) ([]*threatintel.KEVEntry, error) {
	if m.ransomErr != nil {
		return nil, m.ransomErr
	}
	return m.ransomEntries, nil
}

func (m *threatIntelMockKEVRepo) Count(_ context.Context) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.countVal > 0 {
		return m.countVal, nil
	}
	return int64(len(m.entries)), nil
}

func (m *threatIntelMockKEVRepo) DeleteAll(_ context.Context) error {
	m.entries = make(map[string]*threatintel.KEVEntry)
	return nil
}

// ============================================================================

type threatIntelMockSyncStatusRepo struct {
	statuses    map[string]*threatintel.SyncStatus
	getAllErr   error
	getByErr   error
	updateErr  error
}

func newThreatIntelMockSyncStatusRepo() *threatIntelMockSyncStatusRepo {
	return &threatIntelMockSyncStatusRepo{
		statuses: make(map[string]*threatintel.SyncStatus),
	}
}

func (m *threatIntelMockSyncStatusRepo) GetBySource(_ context.Context, source string) (*threatintel.SyncStatus, error) {
	if m.getByErr != nil {
		return nil, m.getByErr
	}
	s, ok := m.statuses[source]
	if !ok {
		return nil, threatintel.ErrSyncStatusNotFound
	}
	return s, nil
}

func (m *threatIntelMockSyncStatusRepo) GetAll(_ context.Context) ([]*threatintel.SyncStatus, error) {
	if m.getAllErr != nil {
		return nil, m.getAllErr
	}
	result := make([]*threatintel.SyncStatus, 0, len(m.statuses))
	for _, s := range m.statuses {
		result = append(result, s)
	}
	return result, nil
}

func (m *threatIntelMockSyncStatusRepo) GetEnabled(_ context.Context) ([]*threatintel.SyncStatus, error) {
	result := make([]*threatintel.SyncStatus, 0)
	for _, s := range m.statuses {
		if s.IsEnabled() {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *threatIntelMockSyncStatusRepo) GetDueForSync(_ context.Context) ([]*threatintel.SyncStatus, error) {
	result := make([]*threatintel.SyncStatus, 0)
	for _, s := range m.statuses {
		if s.IsDueForSync() {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *threatIntelMockSyncStatusRepo) Update(_ context.Context, status *threatintel.SyncStatus) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.statuses[status.SourceName()] = status
	return nil
}

// ============================================================================

type threatIntelMockRepo struct {
	epss       *threatIntelMockEPSSRepo
	kev        *threatIntelMockKEVRepo
	syncStatus *threatIntelMockSyncStatusRepo
	enrichCVEs map[string]*threatintel.ThreatIntelEnrichment
	enrichErr  error
}

func newThreatIntelMockRepo() *threatIntelMockRepo {
	return &threatIntelMockRepo{
		epss:       newThreatIntelMockEPSSRepo(),
		kev:        newThreatIntelMockKEVRepo(),
		syncStatus: newThreatIntelMockSyncStatusRepo(),
		enrichCVEs: make(map[string]*threatintel.ThreatIntelEnrichment),
	}
}

func (m *threatIntelMockRepo) EPSS() threatintel.EPSSRepository       { return m.epss }
func (m *threatIntelMockRepo) KEV() threatintel.KEVRepository         { return m.kev }
func (m *threatIntelMockRepo) SyncStatus() threatintel.SyncStatusRepository { return m.syncStatus }

func (m *threatIntelMockRepo) EnrichCVEs(_ context.Context, cveIDs []string) (map[string]*threatintel.ThreatIntelEnrichment, error) {
	if m.enrichErr != nil {
		return nil, m.enrichErr
	}
	result := make(map[string]*threatintel.ThreatIntelEnrichment, len(cveIDs))
	for _, id := range cveIDs {
		if e, ok := m.enrichCVEs[id]; ok {
			result[id] = e
		}
	}
	return result, nil
}

func (m *threatIntelMockRepo) EnrichCVE(_ context.Context, cveID string) (*threatintel.ThreatIntelEnrichment, error) {
	if m.enrichErr != nil {
		return nil, m.enrichErr
	}
	e, ok := m.enrichCVEs[cveID]
	if !ok {
		return threatintel.NewThreatIntelEnrichment(cveID), nil
	}
	return e, nil
}

// ============================================================================
// Helpers
// ============================================================================

func newThreatIntelService(repo threatintel.ThreatIntelRepository) *app.ThreatIntelService {
	log := logger.NewNop()
	return app.NewThreatIntelService(repo, log)
}

func threatIntelAddEPSSScore(repo *threatIntelMockRepo, cveID string, score, percentile float64) *threatintel.EPSSScore {
	s := threatintel.NewEPSSScore(cveID, score, percentile, "v2024.01.01", time.Now())
	repo.epss.scores[cveID] = s
	return s
}

func threatIntelAddKEVEntry(repo *threatIntelMockRepo, cveID string) *threatintel.KEVEntry {
	e := threatintel.NewKEVEntry(
		cveID, "Vendor", "Product", "Vuln Name", "Description",
		time.Now().Add(-30*24*time.Hour), time.Now().Add(7*24*time.Hour),
		"Known", "Notes", []string{"CWE-79"},
	)
	repo.kev.entries[cveID] = e
	return e
}

func threatIntelAddSyncStatus(repo *threatIntelMockRepo, source string, enabled bool) *threatintel.SyncStatus {
	status := threatintel.ReconstituteSyncStatus(
		shared.NewID(), source, nil,
		threatintel.SyncStatePending, "", 0, 0, nil, 24,
		enabled, nil, time.Now(), time.Now(),
	)
	repo.syncStatus.statuses[source] = status
	return status
}

// ============================================================================
// Tests: GetSyncStatuses
// ============================================================================

func TestThreatIntelService_GetSyncStatuses_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "epss", true)
	threatIntelAddSyncStatus(repo, "kev", true)

	statuses, err := svc.GetSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(statuses) != 2 {
		t.Errorf("expected 2 statuses, got %d", len(statuses))
	}
}

func TestThreatIntelService_GetSyncStatuses_RepoError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.syncStatus.getAllErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetSyncStatuses(ctx)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetSyncStatus
// ============================================================================

func TestThreatIntelService_GetSyncStatus_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "epss", true)

	status, err := svc.GetSyncStatus(ctx, "epss")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if status.SourceName() != "epss" {
		t.Errorf("expected source 'epss', got %q", status.SourceName())
	}
}

func TestThreatIntelService_GetSyncStatus_NotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetSyncStatus(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
	if !errors.Is(err, threatintel.ErrSyncStatusNotFound) {
		t.Errorf("expected ErrSyncStatusNotFound, got %v", err)
	}
}

// ============================================================================
// Tests: SetSyncEnabled
// ============================================================================

func TestThreatIntelService_SetSyncEnabled_Enable(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "epss", false)

	err := svc.SetSyncEnabled(ctx, "epss", true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	status := repo.syncStatus.statuses["epss"]
	if !status.IsEnabled() {
		t.Error("expected sync to be enabled")
	}
}

func TestThreatIntelService_SetSyncEnabled_Disable(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "kev", true)

	err := svc.SetSyncEnabled(ctx, "kev", false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	status := repo.syncStatus.statuses["kev"]
	if status.IsEnabled() {
		t.Error("expected sync to be disabled")
	}
}

func TestThreatIntelService_SetSyncEnabled_NotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	err := svc.SetSyncEnabled(ctx, "nonexistent", true)
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

func TestThreatIntelService_SetSyncEnabled_UpdateError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.syncStatus.updateErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "epss", true)

	err := svc.SetSyncEnabled(ctx, "epss", false)
	if err == nil {
		t.Fatal("expected error when update fails")
	}
}

// ============================================================================
// Tests: EnrichCVEs
// ============================================================================

func TestThreatIntelService_EnrichCVEs_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	enrichment := threatintel.NewThreatIntelEnrichment("CVE-2024-1234").
		WithEPSS(0.85, 99.1).
		WithKEV("2024-01-01", "2024-02-01", "Known")
	repo.enrichCVEs["CVE-2024-1234"] = enrichment

	result, err := svc.EnrichCVEs(ctx, []string{"CVE-2024-1234", "CVE-2024-5678"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 enrichment, got %d", len(result))
	}
	e, ok := result["CVE-2024-1234"]
	if !ok {
		t.Fatal("expected enrichment for CVE-2024-1234")
	}
	if e.EPSSScore == nil || *e.EPSSScore != 0.85 {
		t.Error("expected EPSS score 0.85")
	}
	if !e.InKEV {
		t.Error("expected InKEV to be true")
	}
}

func TestThreatIntelService_EnrichCVEs_RepoError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.enrichErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.EnrichCVEs(ctx, []string{"CVE-2024-1234"})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: EnrichCVE
// ============================================================================

func TestThreatIntelService_EnrichCVE_WithData(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	enrichment := threatintel.NewThreatIntelEnrichment("CVE-2024-1234").WithEPSS(0.5, 95.0)
	repo.enrichCVEs["CVE-2024-1234"] = enrichment

	result, err := svc.EnrichCVE(ctx, "CVE-2024-1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.EPSSScore == nil || *result.EPSSScore != 0.5 {
		t.Error("expected EPSS score 0.5")
	}
}

func TestThreatIntelService_EnrichCVE_NoData(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	result, err := svc.EnrichCVE(ctx, "CVE-9999-0001")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.HasData() {
		t.Error("expected no enrichment data for unknown CVE")
	}
}

func TestThreatIntelService_EnrichCVE_RepoError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.enrichErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.EnrichCVE(ctx, "CVE-2024-1234")
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetEPSSScore
// ============================================================================

func TestThreatIntelService_GetEPSSScore_Found(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddEPSSScore(repo, "CVE-2024-1234", 0.42, 88.5)

	score, err := svc.GetEPSSScore(ctx, "CVE-2024-1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if score.Score() != 0.42 {
		t.Errorf("expected score 0.42, got %f", score.Score())
	}
	if score.Percentile() != 88.5 {
		t.Errorf("expected percentile 88.5, got %f", score.Percentile())
	}
}

func TestThreatIntelService_GetEPSSScore_NotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetEPSSScore(ctx, "CVE-9999-0001")
	if err == nil {
		t.Fatal("expected error for missing EPSS score")
	}
	if !errors.Is(err, threatintel.ErrEPSSNotFound) {
		t.Errorf("expected ErrEPSSNotFound, got %v", err)
	}
}

// ============================================================================
// Tests: GetEPSSScores
// ============================================================================

func TestThreatIntelService_GetEPSSScores_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.1, 50.0)
	threatIntelAddEPSSScore(repo, "CVE-2024-0002", 0.5, 90.0)

	scores, err := svc.GetEPSSScores(ctx, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(scores))
	}
}

func TestThreatIntelService_GetEPSSScores_Empty(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	scores, err := svc.GetEPSSScores(ctx, []string{"CVE-9999-0001"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(scores))
	}
}

// ============================================================================
// Tests: GetHighRiskEPSS
// ============================================================================

func TestThreatIntelService_GetHighRiskEPSS_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.05, 30.0) // Low risk
	threatIntelAddEPSSScore(repo, "CVE-2024-0002", 0.15, 80.0) // High risk
	threatIntelAddEPSSScore(repo, "CVE-2024-0003", 0.50, 95.0) // Critical

	scores, err := svc.GetHighRiskEPSS(ctx, 0.1, 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("expected 2 high-risk scores, got %d", len(scores))
	}
}

func TestThreatIntelService_GetHighRiskEPSS_RepoError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.epss.highRiskErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetHighRiskEPSS(ctx, 0.1, 100)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetKEVEntry
// ============================================================================

func TestThreatIntelService_GetKEVEntry_Found(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddKEVEntry(repo, "CVE-2024-1234")

	entry, err := svc.GetKEVEntry(ctx, "CVE-2024-1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if entry.CVEID() != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %q", entry.CVEID())
	}
	if entry.VendorProject() != "Vendor" {
		t.Errorf("expected 'Vendor', got %q", entry.VendorProject())
	}
}

func TestThreatIntelService_GetKEVEntry_NotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetKEVEntry(ctx, "CVE-9999-0001")
	if err == nil {
		t.Fatal("expected error for missing KEV entry")
	}
	if !errors.Is(err, threatintel.ErrKEVNotFound) {
		t.Errorf("expected ErrKEVNotFound, got %v", err)
	}
}

// ============================================================================
// Tests: IsInKEV
// ============================================================================

func TestThreatIntelService_IsInKEV_True(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddKEVEntry(repo, "CVE-2024-1234")

	result, err := svc.IsInKEV(ctx, "CVE-2024-1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result {
		t.Error("expected CVE to be in KEV")
	}
}

func TestThreatIntelService_IsInKEV_False(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	result, err := svc.IsInKEV(ctx, "CVE-9999-0001")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result {
		t.Error("expected CVE to NOT be in KEV")
	}
}

func TestThreatIntelService_IsInKEV_RepoError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.existsErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.IsInKEV(ctx, "CVE-2024-1234")
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetKEVStats
// ============================================================================

func TestThreatIntelService_GetKEVStats_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddKEVEntry(repo, "CVE-2024-0001")
	threatIntelAddKEVEntry(repo, "CVE-2024-0002")
	threatIntelAddKEVEntry(repo, "CVE-2024-0003")

	repo.kev.pastDueEntries = []*threatintel.KEVEntry{repo.kev.entries["CVE-2024-0001"]}
	repo.kev.recentEntries = []*threatintel.KEVEntry{repo.kev.entries["CVE-2024-0002"], repo.kev.entries["CVE-2024-0003"]}
	repo.kev.ransomEntries = []*threatintel.KEVEntry{repo.kev.entries["CVE-2024-0001"]}

	stats, err := svc.GetKEVStats(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalEntries != 3 {
		t.Errorf("expected total 3, got %d", stats.TotalEntries)
	}
	if stats.PastDueCount != 1 {
		t.Errorf("expected 1 past due, got %d", stats.PastDueCount)
	}
	if stats.RecentlyAddedLast30Days != 2 {
		t.Errorf("expected 2 recently added, got %d", stats.RecentlyAddedLast30Days)
	}
	if stats.RansomwareRelatedCount != 1 {
		t.Errorf("expected 1 ransomware related, got %d", stats.RansomwareRelatedCount)
	}
}

func TestThreatIntelService_GetKEVStats_CountError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.countErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetKEVStats(ctx)
	if err == nil {
		t.Fatal("expected error when Count fails")
	}
}

func TestThreatIntelService_GetKEVStats_PastDueError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.pastDueErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetKEVStats(ctx)
	if err == nil {
		t.Fatal("expected error when GetPastDue fails")
	}
}

func TestThreatIntelService_GetKEVStats_RecentError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.recentErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetKEVStats(ctx)
	if err == nil {
		t.Fatal("expected error when GetRecentlyAdded fails")
	}
}

func TestThreatIntelService_GetKEVStats_RansomwareError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.ransomErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetKEVStats(ctx)
	if err == nil {
		t.Fatal("expected error when GetRansomwareRelated fails")
	}
}

// ============================================================================
// Tests: GetEPSSStats
// ============================================================================

func TestThreatIntelService_GetEPSSStats_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.05, 30.0) // Low
	threatIntelAddEPSSScore(repo, "CVE-2024-0002", 0.15, 80.0) // High (> 0.1)
	threatIntelAddEPSSScore(repo, "CVE-2024-0003", 0.50, 95.0) // Critical (> 0.3)

	// Set up highRiskFn to handle different thresholds
	repo.epss.highRiskFn = func(_ context.Context, threshold float64, _ int) ([]*threatintel.EPSSScore, error) {
		result := make([]*threatintel.EPSSScore, 0)
		for _, s := range repo.epss.scores {
			if s.Score() > threshold {
				result = append(result, s)
			}
		}
		return result, nil
	}

	stats, err := svc.GetEPSSStats(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalScores != 3 {
		t.Errorf("expected total 3, got %d", stats.TotalScores)
	}
	if stats.HighRiskCount != 2 {
		t.Errorf("expected 2 high-risk (> 0.1), got %d", stats.HighRiskCount)
	}
	if stats.CriticalRiskCount != 1 {
		t.Errorf("expected 1 critical (> 0.3), got %d", stats.CriticalRiskCount)
	}
}

func TestThreatIntelService_GetEPSSStats_CountError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.epss.countErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetEPSSStats(ctx)
	if err == nil {
		t.Fatal("expected error when Count fails")
	}
}

func TestThreatIntelService_GetEPSSStats_HighRiskError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.epss.highRiskErr = errors.New("db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	_, err := svc.GetEPSSStats(ctx)
	if err == nil {
		t.Fatal("expected error when GetHighRisk fails")
	}
}

// ============================================================================
// Tests: GetThreatIntelStats
// ============================================================================

func TestThreatIntelService_GetThreatIntelStats_Success(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// Set up EPSS data
	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.05, 30.0)
	repo.epss.highRiskFn = func(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
		return nil, nil
	}

	// Set up KEV data
	threatIntelAddKEVEntry(repo, "CVE-2024-0001")

	// Set up sync statuses
	threatIntelAddSyncStatus(repo, "epss", true)
	threatIntelAddSyncStatus(repo, "kev", true)

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.EPSS == nil {
		t.Error("expected EPSS stats to be present")
	}
	if stats.KEV == nil {
		t.Error("expected KEV stats to be present")
	}
	if len(stats.SyncStatuses) != 2 {
		t.Errorf("expected 2 sync statuses, got %d", len(stats.SyncStatuses))
	}
}

func TestThreatIntelService_GetThreatIntelStats_EPSSFailsGracefully(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.epss.countErr = errors.New("epss db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// KEV should still work
	threatIntelAddKEVEntry(repo, "CVE-2024-0001")
	threatIntelAddSyncStatus(repo, "kev", true)

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if stats.EPSS != nil {
		t.Error("expected EPSS stats to be nil on error")
	}
	if stats.KEV == nil {
		t.Error("expected KEV stats to be present despite EPSS failure")
	}
}

func TestThreatIntelService_GetThreatIntelStats_KEVFailsGracefully(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.kev.countErr = errors.New("kev db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// EPSS should still work
	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.05, 30.0)
	repo.epss.highRiskFn = func(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
		return nil, nil
	}
	threatIntelAddSyncStatus(repo, "epss", true)

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if stats.KEV != nil {
		t.Error("expected KEV stats to be nil on error")
	}
	if stats.EPSS == nil {
		t.Error("expected EPSS stats to be present despite KEV failure")
	}
}

func TestThreatIntelService_GetThreatIntelStats_SyncStatusFailsGracefully(t *testing.T) {
	repo := newThreatIntelMockRepo()
	repo.syncStatus.getAllErr = errors.New("sync status db error")
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// EPSS and KEV setup
	threatIntelAddEPSSScore(repo, "CVE-2024-0001", 0.05, 30.0)
	repo.epss.highRiskFn = func(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
		return nil, nil
	}

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if stats.SyncStatuses == nil {
		t.Fatal("expected SyncStatuses to be non-nil (empty slice)")
	}
	if len(stats.SyncStatuses) != 0 {
		t.Errorf("expected 0 sync statuses on error, got %d", len(stats.SyncStatuses))
	}
}

func TestThreatIntelService_GetThreatIntelStats_SyncStatusDTOFields(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// Create a status with sync history
	status := threatIntelAddSyncStatus(repo, "epss", true)
	status.MarkSyncStarted()
	status.MarkSyncSuccess(50000, 1200)

	// Empty EPSS/KEV to avoid errors
	repo.epss.highRiskFn = func(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
		return nil, nil
	}

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.SyncStatuses) != 1 {
		t.Fatalf("expected 1 sync status, got %d", len(stats.SyncStatuses))
	}
	dto := stats.SyncStatuses[0]
	if dto.Source != "epss" {
		t.Errorf("expected source 'epss', got %q", dto.Source)
	}
	if !dto.Enabled {
		t.Error("expected enabled to be true")
	}
	if dto.LastSyncStatus != "success" {
		t.Errorf("expected last sync status 'success', got %q", dto.LastSyncStatus)
	}
	if dto.RecordsSynced != 50000 {
		t.Errorf("expected 50000 records synced, got %d", dto.RecordsSynced)
	}
	if dto.LastSyncAt == nil {
		t.Error("expected LastSyncAt to be set")
	}
	if dto.NextSyncAt == nil {
		t.Error("expected NextSyncAt to be set")
	}
	if dto.LastError != nil {
		t.Error("expected LastError to be nil on success")
	}
}

func TestThreatIntelService_GetThreatIntelStats_SyncStatusWithError(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	status := threatIntelAddSyncStatus(repo, "kev", true)
	status.MarkSyncStarted()
	status.MarkSyncFailed("connection timeout")

	repo.epss.highRiskFn = func(_ context.Context, _ float64, _ int) ([]*threatintel.EPSSScore, error) {
		return nil, nil
	}

	stats, err := svc.GetThreatIntelStats(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.SyncStatuses) != 1 {
		t.Fatalf("expected 1 sync status, got %d", len(stats.SyncStatuses))
	}
	dto := stats.SyncStatuses[0]
	if dto.LastSyncStatus != "failed" {
		t.Errorf("expected status 'failed', got %q", dto.LastSyncStatus)
	}
	if dto.LastError == nil {
		t.Fatal("expected LastError to be set on failure")
	}
	if *dto.LastError != "connection timeout" {
		t.Errorf("expected error 'connection timeout', got %q", *dto.LastError)
	}
}

// ============================================================================
// Tests: SyncAll (basic behavior without HTTP)
// ============================================================================

func TestThreatIntelService_SyncAll_DisabledSources(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// Both sources disabled
	threatIntelAddSyncStatus(repo, "epss", false)
	threatIntelAddSyncStatus(repo, "kev", false)

	results := svc.SyncAll(ctx)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Error == nil {
			t.Errorf("expected error for disabled source %q", r.Source)
		}
		if !errors.Is(r.Error, threatintel.ErrSyncDisabled) {
			t.Errorf("expected ErrSyncDisabled for source %q, got %v", r.Source, r.Error)
		}
	}
}

func TestThreatIntelService_SyncEPSS_StatusNotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// No sync status exists for "epss"
	result := svc.SyncEPSS(ctx)
	if result.Error == nil {
		t.Fatal("expected error when sync status not found")
	}
}

func TestThreatIntelService_SyncKEV_StatusNotFound(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	// No sync status exists for "kev"
	result := svc.SyncKEV(ctx)
	if result.Error == nil {
		t.Fatal("expected error when sync status not found")
	}
}

func TestThreatIntelService_SyncEPSS_Disabled(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "epss", false)

	result := svc.SyncEPSS(ctx)
	if result.Error == nil {
		t.Fatal("expected error for disabled sync")
	}
	if !errors.Is(result.Error, threatintel.ErrSyncDisabled) {
		t.Errorf("expected ErrSyncDisabled, got %v", result.Error)
	}
	if result.Source != "epss" {
		t.Errorf("expected source 'epss', got %q", result.Source)
	}
}

func TestThreatIntelService_SyncKEV_Disabled(t *testing.T) {
	repo := newThreatIntelMockRepo()
	svc := newThreatIntelService(repo)
	ctx := context.Background()

	threatIntelAddSyncStatus(repo, "kev", false)

	result := svc.SyncKEV(ctx)
	if result.Error == nil {
		t.Fatal("expected error for disabled sync")
	}
	if !errors.Is(result.Error, threatintel.ErrSyncDisabled) {
		t.Errorf("expected ErrSyncDisabled, got %v", result.Error)
	}
	if result.Source != "kev" {
		t.Errorf("expected source 'kev', got %q", result.Source)
	}
}
