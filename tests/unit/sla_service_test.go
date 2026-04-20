package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/sla"
	"github.com/openctemio/api/pkg/domain/shared"
	sladom "github.com/openctemio/api/pkg/domain/sla"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Repository
// =============================================================================

type mockSLARepo struct {
	policies    map[string]*sladom.Policy
	createErr   error
	getByIDErr  error
	getByAsset  error
	getDefault  error
	updateErr   error
	deleteErr   error
	listErr     error
	existsErr   error
	existsVal   bool
}

func newMockSLARepo() *mockSLARepo {
	return &mockSLARepo{
		policies: make(map[string]*sladom.Policy),
	}
}

func (m *mockSLARepo) Create(_ context.Context, policy *sladom.Policy) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.policies[policy.ID().String()] = policy
	return nil
}

func (m *mockSLARepo) GetByID(_ context.Context, id shared.ID) (*sladom.Policy, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	if p, ok := m.policies[id.String()]; ok {
		return p, nil
	}
	return nil, sladom.ErrNotFound
}

func (m *mockSLARepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*sladom.Policy, error) {
	return nil, nil
}

func (m *mockSLARepo) GetByAsset(_ context.Context, tenantID, assetID shared.ID) (*sladom.Policy, error) {
	if m.getByAsset != nil {
		return nil, m.getByAsset
	}
	for _, p := range m.policies {
		if p.TenantID() == tenantID && p.AssetID() != nil && *p.AssetID() == assetID {
			return p, nil
		}
	}
	return nil, sladom.ErrNotFound
}

func (m *mockSLARepo) GetTenantDefault(_ context.Context, tenantID shared.ID) (*sladom.Policy, error) {
	if m.getDefault != nil {
		return nil, m.getDefault
	}
	for _, p := range m.policies {
		if p.TenantID() == tenantID && p.IsDefault() {
			return p, nil
		}
	}
	return nil, sladom.ErrNotFound
}

func (m *mockSLARepo) Update(_ context.Context, policy *sladom.Policy) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.policies[policy.ID().String()] = policy
	return nil
}

func (m *mockSLARepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.policies[id.String()]; !ok {
		return sladom.ErrNotFound
	}
	delete(m.policies, id.String())
	return nil
}

func (m *mockSLARepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*sladom.Policy, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var result []*sladom.Policy
	for _, p := range m.policies {
		if p.TenantID() == tenantID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *mockSLARepo) ExistsByAsset(_ context.Context, _ shared.ID) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	return m.existsVal, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestSLAService(repo *mockSLARepo) *sla.Service {
	return sla.NewService(repo, logger.NewNop())
}

func makeTestPolicy(tenantID shared.ID, name string, isDefault bool) *sladom.Policy {
	now := time.Now().UTC()
	id := shared.NewID()
	return sladom.Reconstitute(
		id, tenantID, nil, name, "test description", isDefault,
		2, 15, 30, 60, 90,
		80, false, nil, true,
		now, now,
	)
}

func makeTestPolicyWithAsset(tenantID, assetID shared.ID, name string) *sladom.Policy {
	now := time.Now().UTC()
	id := shared.NewID()
	return sladom.Reconstitute(
		id, tenantID, &assetID, name, "asset policy", false,
		1, 7, 14, 30, 60,
		75, false, nil, true,
		now, now,
	)
}

func validSLACreateInput(tenantID string) sla.CreatePolicyInput {
	return sla.CreatePolicyInput{
		TenantID:            tenantID,
		Name:                "Test SLA Policy",
		Description:         "A test policy",
		IsDefault:           false,
		CriticalDays:        2,
		HighDays:            15,
		MediumDays:          30,
		LowDays:             60,
		InfoDays:            90,
		WarningThresholdPct: 80,
		EscalationEnabled:   false,
	}
}

func slaIntPtr(v int) *int       { return &v }
func slaStrPtr(v string) *string { return &v }
func slaBoolPtr(v bool) *bool    { return &v }

// =============================================================================
// CreateSLAPolicy Tests
// =============================================================================

func TestCreateSLAPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())

	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy == nil {
		t.Fatal("expected policy to be non-nil")
	}
	if policy.Name() != "Test SLA Policy" {
		t.Errorf("expected name 'Test SLA Policy', got '%s'", policy.Name())
	}
	if policy.CriticalDays() != 2 {
		t.Errorf("expected critical days 2, got %d", policy.CriticalDays())
	}
	if policy.HighDays() != 15 {
		t.Errorf("expected high days 15, got %d", policy.HighDays())
	}
	if len(repo.policies) != 1 {
		t.Errorf("expected 1 policy in repo, got %d", len(repo.policies))
	}
}

func TestCreateSLAPolicy_InvalidTenantID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	input := validSLACreateInput("not-a-uuid")
	_, err := svc.CreateSLAPolicy(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateSLAPolicy_InvalidDaysOrder(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.CriticalDays = 20
	input.HighDays = 15 // critical > high = invalid

	_, err := svc.CreateSLAPolicy(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid days order")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateSLAPolicy_InvalidAssetID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.AssetID = "bad-uuid"

	_, err := svc.CreateSLAPolicy(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateSLAPolicy_RepoCreateError(t *testing.T) {
	repo := newMockSLARepo()
	repo.createErr = errors.New("database error")
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())

	_, err := svc.CreateSLAPolicy(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo create failure")
	}
}

func TestCreateSLAPolicy_WithAssetID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.AssetID = assetID.String()

	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.AssetID() == nil {
		t.Fatal("expected asset ID to be set")
	}
	if *policy.AssetID() != assetID {
		t.Errorf("expected asset ID %s, got %s", assetID, *policy.AssetID())
	}
}

func TestCreateSLAPolicy_WithDescription(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.Description = "Custom description"

	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.Description() != "Custom description" {
		t.Errorf("expected description 'Custom description', got '%s'", policy.Description())
	}
}

func TestCreateSLAPolicy_WithWarningThreshold(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.WarningThresholdPct = 70

	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.WarningThresholdPct() != 70 {
		t.Errorf("expected warning threshold 70, got %d", policy.WarningThresholdPct())
	}
}

func TestCreateSLAPolicy_WithEscalation(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	input := validSLACreateInput(tenantID.String())
	input.EscalationEnabled = true
	input.EscalationConfig = map[string]any{"notify": "manager@example.com"}

	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !policy.EscalationEnabled() {
		t.Error("expected escalation to be enabled")
	}
}

// =============================================================================
// GetSLAPolicy Tests
// =============================================================================

func TestGetSLAPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Existing Policy", false)
	repo.policies[existing.ID().String()] = existing

	policy, err := svc.GetSLAPolicy(context.Background(), existing.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.ID() != existing.ID() {
		t.Errorf("expected ID %s, got %s", existing.ID(), policy.ID())
	}
}

func TestGetSLAPolicy_InvalidID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetSLAPolicy(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetSLAPolicy_NotFound(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetSLAPolicy(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// GetAssetSLAPolicy Tests
// =============================================================================

func TestGetAssetSLAPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	existing := makeTestPolicyWithAsset(tenantID, assetID, "Asset Policy")
	repo.policies[existing.ID().String()] = existing

	policy, err := svc.GetAssetSLAPolicy(context.Background(), tenantID.String(), assetID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.Name() != "Asset Policy" {
		t.Errorf("expected name 'Asset Policy', got '%s'", policy.Name())
	}
}

func TestGetAssetSLAPolicy_InvalidTenantID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetAssetSLAPolicy(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetAssetSLAPolicy_InvalidAssetID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetAssetSLAPolicy(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetAssetSLAPolicy_NotFound(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetAssetSLAPolicy(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// GetTenantDefaultPolicy Tests
// =============================================================================

func TestGetTenantDefaultPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Default Policy", true)
	repo.policies[existing.ID().String()] = existing

	policy, err := svc.GetTenantDefaultPolicy(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !policy.IsDefault() {
		t.Error("expected policy to be default")
	}
}

func TestGetTenantDefaultPolicy_InvalidTenantID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetTenantDefaultPolicy(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetTenantDefaultPolicy_NotFound(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetTenantDefaultPolicy(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// UpdateSLAPolicy Tests
// =============================================================================

func TestUpdateSLAPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Old Name", false)
	repo.policies[existing.ID().String()] = existing

	newName := "New Name"
	input := sla.UpdatePolicyInput{
		Name: &newName,
	}

	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.Name() != "New Name" {
		t.Errorf("expected name 'New Name', got '%s'", policy.Name())
	}
}

func TestUpdateSLAPolicy_InvalidID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.UpdateSLAPolicy(context.Background(), "bad-uuid", shared.NewID().String(), sla.UpdatePolicyInput{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestUpdateSLAPolicy_NotFound(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.UpdateSLAPolicy(context.Background(), shared.NewID().String(), shared.NewID().String(), sla.UpdatePolicyInput{})
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateSLAPolicy_IDORPrevention(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "My Policy", false)
	repo.policies[existing.ID().String()] = existing

	_, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), otherTenantID.String(), sla.UpdatePolicyInput{})
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR, got %v", err)
	}
}

func TestUpdateSLAPolicy_NameOnly(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Old Name", false)
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{Name: slaStrPtr("Updated Name")}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.Name() != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got '%s'", policy.Name())
	}
	// Days should remain unchanged
	if policy.CriticalDays() != 2 {
		t.Errorf("expected critical days unchanged at 2, got %d", policy.CriticalDays())
	}
}

func TestUpdateSLAPolicy_DaysPartial(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Policy", false)
	repo.policies[existing.ID().String()] = existing

	// Only update critical days (1 <= 15 <= 30 <= 60 <= 90 still valid)
	input := sla.UpdatePolicyInput{CriticalDays: slaIntPtr(1)}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.CriticalDays() != 1 {
		t.Errorf("expected critical days 1, got %d", policy.CriticalDays())
	}
	if policy.HighDays() != 15 {
		t.Errorf("expected high days unchanged at 15, got %d", policy.HighDays())
	}
}

func TestUpdateSLAPolicy_DaysOrderViolation(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Policy", false)
	repo.policies[existing.ID().String()] = existing

	// Set critical higher than high (violates order)
	input := sla.UpdatePolicyInput{CriticalDays: slaIntPtr(100)}
	_, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err == nil {
		t.Fatal("expected error for days order violation")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestUpdateSLAPolicy_WarningThreshold(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Policy", false)
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{WarningThresholdPct: slaIntPtr(50)}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.WarningThresholdPct() != 50 {
		t.Errorf("expected warning threshold 50, got %d", policy.WarningThresholdPct())
	}
}

func TestUpdateSLAPolicy_EnableEscalation(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Policy", false)
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{
		EscalationEnabled: slaBoolPtr(true),
		EscalationConfig:  map[string]any{"channel": "#alerts"},
	}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !policy.EscalationEnabled() {
		t.Error("expected escalation to be enabled")
	}
}

func TestUpdateSLAPolicy_DisableEscalation(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	now := time.Now().UTC()
	existing := sladom.Reconstitute(
		shared.NewID(), tenantID, nil, "Policy", "", false,
		2, 15, 30, 60, 90,
		80, true, map[string]any{"notify": true}, true,
		now, now,
	)
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{EscalationEnabled: slaBoolPtr(false)}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.EscalationEnabled() {
		t.Error("expected escalation to be disabled")
	}
}

func TestUpdateSLAPolicy_Activate(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	now := time.Now().UTC()
	existing := sladom.Reconstitute(
		shared.NewID(), tenantID, nil, "Policy", "", false,
		2, 15, 30, 60, 90,
		80, false, nil, false, // isActive = false
		now, now,
	)
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{IsActive: slaBoolPtr(true)}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !policy.IsActive() {
		t.Error("expected policy to be active")
	}
}

func TestUpdateSLAPolicy_Deactivate(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Policy", false) // isActive = true
	repo.policies[existing.ID().String()] = existing

	input := sla.UpdatePolicyInput{IsActive: slaBoolPtr(false)}
	policy, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy.IsActive() {
		t.Error("expected policy to be inactive")
	}
}

// =============================================================================
// DeleteSLAPolicy Tests
// =============================================================================

func TestDeleteSLAPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "To Delete", false)
	repo.policies[existing.ID().String()] = existing

	err := svc.DeleteSLAPolicy(context.Background(), existing.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(repo.policies) != 0 {
		t.Errorf("expected 0 policies in repo, got %d", len(repo.policies))
	}
}

func TestDeleteSLAPolicy_InvalidID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	err := svc.DeleteSLAPolicy(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeleteSLAPolicy_NotFound(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	policyID := shared.NewID()
	err := svc.DeleteSLAPolicy(context.Background(), policyID.String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteSLAPolicy_IDORPrevention(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "My Policy", false)
	repo.policies[existing.ID().String()] = existing

	err := svc.DeleteSLAPolicy(context.Background(), existing.ID().String(), otherTenantID.String())
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR, got %v", err)
	}
	// Policy should not be deleted
	if len(repo.policies) != 1 {
		t.Error("policy should not have been deleted")
	}
}

func TestDeleteSLAPolicy_CannotDeleteDefaultPolicy(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "Default", true) // isDefault = true
	repo.policies[existing.ID().String()] = existing

	err := svc.DeleteSLAPolicy(context.Background(), existing.ID().String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error when deleting default policy")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
	// Policy should not be deleted
	if len(repo.policies) != 1 {
		t.Error("default policy should not have been deleted")
	}
}

// =============================================================================
// ListTenantPolicies Tests
// =============================================================================

func TestListTenantPolicies_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	p1 := makeTestPolicy(tenantID, "Policy 1", true)
	p2 := makeTestPolicy(tenantID, "Policy 2", false)
	repo.policies[p1.ID().String()] = p1
	repo.policies[p2.ID().String()] = p2

	// Add a policy for another tenant
	otherTenantID := shared.NewID()
	p3 := makeTestPolicy(otherTenantID, "Other Policy", false)
	repo.policies[p3.ID().String()] = p3

	policies, err := svc.ListTenantPolicies(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestListTenantPolicies_InvalidTenantID(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.ListTenantPolicies(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestListTenantPolicies_RepoError(t *testing.T) {
	repo := newMockSLARepo()
	repo.listErr = errors.New("database failure")
	svc := newTestSLAService(repo)

	_, err := svc.ListTenantPolicies(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// CalculateSLADeadline Tests
// =============================================================================

func TestCalculateSLADeadline_WithAssetPolicy(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	policy := makeTestPolicyWithAsset(tenantID, assetID, "Asset Policy")
	repo.policies[policy.ID().String()] = policy

	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline, err := svc.CalculateSLADeadline(context.Background(), tenantID.String(), assetID.String(), vulnerability.SeverityCritical, detectedAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Asset policy has criticalDays=1
	expected := detectedAt.Add(1 * 24 * time.Hour)
	if !deadline.Equal(expected) {
		t.Errorf("expected deadline %v, got %v", expected, deadline)
	}
}

func TestCalculateSLADeadline_WithTenantDefault(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	defaultPolicy := makeTestPolicy(tenantID, "Default", true)
	repo.policies[defaultPolicy.ID().String()] = defaultPolicy

	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline, err := svc.CalculateSLADeadline(context.Background(), tenantID.String(), "", vulnerability.SeverityHigh, detectedAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Default policy has highDays=15
	expected := detectedAt.Add(15 * 24 * time.Hour)
	if !deadline.Equal(expected) {
		t.Errorf("expected deadline %v, got %v", expected, deadline)
	}
}

func TestCalculateSLADeadline_FallbackToDefaults(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// No policy in repo, should fall back to sladom.DefaultSLADays
	deadline, err := svc.CalculateSLADeadline(context.Background(), tenantID.String(), "", vulnerability.SeverityMedium, detectedAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := detectedAt.Add(30 * 24 * time.Hour) // DefaultSLADays["medium"] = 30
	if !deadline.Equal(expected) {
		t.Errorf("expected deadline %v, got %v", expected, deadline)
	}
}

func TestCalculateSLADeadline_DifferentSeverities(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		severity vulnerability.Severity
		days     int
	}{
		{vulnerability.SeverityCritical, 2},
		{vulnerability.SeverityHigh, 15},
		{vulnerability.SeverityMedium, 30},
		{vulnerability.SeverityLow, 60},
		{vulnerability.SeverityInfo, 90},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			deadline, err := svc.CalculateSLADeadline(context.Background(), tenantID.String(), "", tt.severity, detectedAt)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			expected := detectedAt.Add(time.Duration(tt.days) * 24 * time.Hour)
			if !deadline.Equal(expected) {
				t.Errorf("expected deadline %v, got %v", expected, deadline)
			}
		})
	}
}

// =============================================================================
// CheckSLACompliance Tests
// =============================================================================

func TestCheckSLACompliance_OnTrack(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	defaultPolicy := makeTestPolicy(tenantID, "Default", true)
	repo.policies[defaultPolicy.ID().String()] = defaultPolicy

	// Detected very recently, should be on track
	detectedAt := time.Now().Add(-1 * time.Hour)

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityCritical, detectedAt, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != "on_track" {
		t.Errorf("expected status 'on_track', got '%s'", result.Status)
	}
	if !result.IsCompliant {
		t.Error("expected IsCompliant to be true")
	}
}

func TestCheckSLACompliance_Warning(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	defaultPolicy := makeTestPolicy(tenantID, "Default", true) // warningThresholdPct=80, criticalDays=2
	repo.policies[defaultPolicy.ID().String()] = defaultPolicy

	// For critical (2 days), 80% warning = 1.6 days elapsed
	// Detect ~1.8 days ago to be in warning territory
	detectedAt := time.Now().Add(-43 * time.Hour) // ~1.79 days

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityCritical, detectedAt, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != "warning" {
		t.Errorf("expected status 'warning', got '%s'", result.Status)
	}
	if !result.IsCompliant {
		t.Error("expected IsCompliant to be true during warning")
	}
}

func TestCheckSLACompliance_Overdue(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	now := time.Now().UTC()
	// Create policy with escalation enabled
	existing := sladom.Reconstitute(
		shared.NewID(), tenantID, nil, "Default", "", true,
		2, 15, 30, 60, 90,
		80, true, map[string]any{"notify": true}, true,
		now, now,
	)
	repo.policies[existing.ID().String()] = existing

	// Detected 5 days ago, critical SLA is 2 days -> overdue
	detectedAt := time.Now().Add(-5 * 24 * time.Hour)

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityCritical, detectedAt, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != "overdue" {
		t.Errorf("expected status 'overdue', got '%s'", result.Status)
	}
	if result.IsCompliant {
		t.Error("expected IsCompliant to be false when overdue")
	}
	if !result.EscalationNeeded {
		t.Error("expected EscalationNeeded to be true when overdue with escalation enabled")
	}
}

func TestCheckSLACompliance_Exceeded(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	defaultPolicy := makeTestPolicy(tenantID, "Default", true) // criticalDays=2
	repo.policies[defaultPolicy.ID().String()] = defaultPolicy

	// Detected 5 days ago, resolved 3 days ago (after 2-day SLA)
	detectedAt := time.Now().Add(-5 * 24 * time.Hour)
	resolvedAt := time.Now().Add(-2 * 24 * time.Hour) // resolved 3 days after detection

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityCritical, detectedAt, &resolvedAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != "exceeded" {
		t.Errorf("expected status 'exceeded', got '%s'", result.Status)
	}
	if result.IsCompliant {
		t.Error("expected IsCompliant to be false when exceeded")
	}
}

func TestCheckSLACompliance_ResolvedBeforeDeadline(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	defaultPolicy := makeTestPolicy(tenantID, "Default", true) // criticalDays=2
	repo.policies[defaultPolicy.ID().String()] = defaultPolicy

	// Detected 3 days ago, resolved 2.5 days ago (within 2-day SLA window)
	detectedAt := time.Now().Add(-3 * 24 * time.Hour)
	resolvedAt := detectedAt.Add(1 * 24 * time.Hour) // resolved 1 day after detection

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityCritical, detectedAt, &resolvedAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != "on_track" {
		t.Errorf("expected status 'on_track', got '%s'", result.Status)
	}
	if !result.IsCompliant {
		t.Error("expected IsCompliant to be true when resolved before deadline")
	}
}

func TestCheckSLACompliance_NoPolicyUsesDefaults(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()

	// No policies in repo
	detectedAt := time.Now().Add(-1 * time.Hour)

	result, err := svc.CheckSLACompliance(context.Background(), tenantID.String(), "", vulnerability.SeverityLow, detectedAt, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// DefaultSLADays["low"] = 60 days, detected 1 hour ago -> on_track
	if result.Status != "on_track" {
		t.Errorf("expected status 'on_track', got '%s'", result.Status)
	}
	if result.DaysRemaining < 59 {
		t.Errorf("expected ~60 days remaining, got %d", result.DaysRemaining)
	}
}

// =============================================================================
// CreateDefaultTenantPolicy Tests
// =============================================================================

func TestCreateDefaultTenantPolicy_Success(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()

	policy, err := svc.CreateDefaultTenantPolicy(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if policy == nil {
		t.Fatal("expected policy to be non-nil")
	}
	if policy.Name() != "Default SLA Policy" {
		t.Errorf("expected name 'Default SLA Policy', got '%s'", policy.Name())
	}
	if !policy.IsDefault() {
		t.Error("expected policy to be default")
	}
	if policy.CriticalDays() != sladom.DefaultSLADays["critical"] {
		t.Errorf("expected critical days %d, got %d", sladom.DefaultSLADays["critical"], policy.CriticalDays())
	}
	if policy.HighDays() != sladom.DefaultSLADays["high"] {
		t.Errorf("expected high days %d, got %d", sladom.DefaultSLADays["high"], policy.HighDays())
	}
	if policy.MediumDays() != sladom.DefaultSLADays["medium"] {
		t.Errorf("expected medium days %d, got %d", sladom.DefaultSLADays["medium"], policy.MediumDays())
	}
	if policy.LowDays() != sladom.DefaultSLADays["low"] {
		t.Errorf("expected low days %d, got %d", sladom.DefaultSLADays["low"], policy.LowDays())
	}
	if policy.InfoDays() != sladom.DefaultSLADays["info"] {
		t.Errorf("expected info days %d, got %d", sladom.DefaultSLADays["info"], policy.InfoDays())
	}
	if policy.WarningThresholdPct() != 80 {
		t.Errorf("expected warning threshold 80, got %d", policy.WarningThresholdPct())
	}
	if policy.EscalationEnabled() {
		t.Error("expected escalation to be disabled")
	}
	if len(repo.policies) != 1 {
		t.Errorf("expected 1 policy in repo, got %d", len(repo.policies))
	}
}
