package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// =============================================================================
// Mock Repository
// =============================================================================

type mockSLARepo struct {
	policies         map[string]*sladom.Policy
	createErr        error
	getByIDErr       error
	getByAsset       error
	getDefault       error
	updateErr        error
	deleteErr        error
	listErr          error
	makeDefaultCalls int
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

func (m *mockSLARepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sladom.Policy, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	if p, ok := m.policies[id.String()]; ok && p.TenantID() == tenantID {
		return p, nil
	}
	return nil, sladom.ErrNotFound
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
		if p.TenantID() == tenantID && p.IsDefault() && p.IsActive() {
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

func (m *mockSLARepo) Delete(_ context.Context, tenantID, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if p, ok := m.policies[id.String()]; !ok || p.TenantID() != tenantID {
		return sladom.ErrNotFound
	}
	delete(m.policies, id.String())
	return nil
}

func (m *mockSLARepo) HasAssetOverride(_ context.Context, _ shared.ID) (bool, error) {
	return false, nil
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

func (m *mockSLARepo) UpdateMakingDefault(_ context.Context, policy *sladom.Policy) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.makeDefaultCalls++
	for _, p := range m.policies {
		if p.TenantID() == policy.TenantID() && p.AssetID() == nil && p.IsDefault() && p.ID() != policy.ID() {
			p.SetDefault(false)
		}
	}
	m.policies[policy.ID().String()] = policy
	return nil
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
		EscalationEnabled:   slaBoolPtr(false),
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

// A create never replaces the tenant default: only the first tenant-wide
// policy may become the default.
func TestCreateSLAPolicy_DoesNotReplaceDefault(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()

	in1 := validSLACreateInput(tenantID.String())
	in1.Name = "Default A"
	in1.IsDefault = true
	p1, err := svc.CreateSLAPolicy(context.Background(), in1)
	if err != nil {
		t.Fatalf("create p1: %v", err)
	}
	if !p1.IsDefault() {
		t.Fatal("the tenant's first policy asking for default should become it")
	}

	in2 := validSLACreateInput(tenantID.String())
	in2.Name = "Default B"
	in2.IsDefault = true
	p2, err := svc.CreateSLAPolicy(context.Background(), in2)
	if err != nil {
		t.Fatalf("create p2: %v", err)
	}
	if p2.IsDefault() {
		t.Error("a create must not take the default from an existing one")
	}
	if !repo.policies[p1.ID().String()].IsDefault() {
		t.Error("existing default was demoted by a create")
	}
	if repo.makeDefaultCalls != 0 {
		t.Error("create must not swap defaults")
	}

	// Without asking, no default either; an asset policy is never the default.
	in3 := validSLACreateInput(shared.NewID().String())
	if p3, _ := svc.CreateSLAPolicy(context.Background(), in3); p3 == nil || p3.IsDefault() {
		t.Error("create without is_default must not be default")
	}
	in4 := validSLACreateInput(shared.NewID().String())
	in4.IsDefault = true
	in4.AssetID = shared.NewID().String()
	if p4, err := svc.CreateSLAPolicy(context.Background(), in4); err != nil || p4.IsDefault() {
		t.Errorf("asset policy must not be default: %v", err)
	}
}

func TestCreateSLAPolicy_DefaultIsPerTenant(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	a, b := shared.NewID(), shared.NewID()
	for _, tn := range []shared.ID{a, b} {
		in := validSLACreateInput(tn.String())
		in.IsDefault = true
		p, err := svc.CreateSLAPolicy(context.Background(), in)
		if err != nil || !p.IsDefault() {
			t.Fatalf("tenant %s first policy should be default (err=%v)", tn, err)
		}
	}
}

func TestUpdateSLAPolicy_MakeDefaultSwapsInOneCall(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID, other := shared.NewID(), shared.NewID()
	old := makeTestPolicy(tenantID, "Old", true)
	next := makeTestPolicy(tenantID, "Next", false)
	foreign := makeTestPolicy(other, "Foreign default", true)
	for _, p := range []*sladom.Policy{old, next, foreign} {
		repo.policies[p.ID().String()] = p
	}

	got, err := svc.UpdateSLAPolicy(context.Background(), next.ID().String(), tenantID.String(), sla.UpdatePolicyInput{IsDefault: slaBoolPtr(true)})
	if err != nil {
		t.Fatalf("make default: %v", err)
	}
	if !got.IsDefault() || old.IsDefault() {
		t.Fatalf("default not swapped: next=%v old=%v", got.IsDefault(), old.IsDefault())
	}
	if repo.makeDefaultCalls != 1 {
		t.Errorf("swap must go through the transactional repo call once, got %d", repo.makeDefaultCalls)
	}
	if !foreign.IsDefault() {
		t.Error("another tenant's default was touched")
	}
}

func TestUpdateSLAPolicy_MakeDefaultRules(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()
	inactive := sladom.Reconstitute(shared.NewID(), tenantID, nil, "Inactive", "", false,
		2, 15, 30, 60, 90, 80, false, nil, false, time.Now().UTC(), time.Now().UTC())
	assetID := shared.NewID()
	assetPol := makeTestPolicyWithAsset(tenantID, assetID, "Asset")
	repo.policies[inactive.ID().String()] = inactive
	repo.policies[assetPol.ID().String()] = assetPol

	_, err := svc.UpdateSLAPolicy(context.Background(), inactive.ID().String(), tenantID.String(), sla.UpdatePolicyInput{IsDefault: slaBoolPtr(true)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("inactive policy as default: want validation error, got %v", err)
	}
	_, err = svc.UpdateSLAPolicy(context.Background(), assetPol.ID().String(), tenantID.String(), sla.UpdatePolicyInput{IsDefault: slaBoolPtr(true)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("asset policy as default: want validation error, got %v", err)
	}
	// Activating and defaulting in one request is allowed.
	if _, err := svc.UpdateSLAPolicy(context.Background(), inactive.ID().String(), tenantID.String(),
		sla.UpdatePolicyInput{IsDefault: slaBoolPtr(true), IsActive: slaBoolPtr(true)}); err != nil {
		t.Errorf("activate+default: %v", err)
	}
}

func TestUpdateSLAPolicy_DefaultCannotBeDeactivatedOrUnset(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()
	def := makeTestPolicy(tenantID, "Default", true)
	repo.policies[def.ID().String()] = def

	for name, in := range map[string]sla.UpdatePolicyInput{
		"deactivate": {IsActive: slaBoolPtr(false)},
		"unset":      {IsDefault: slaBoolPtr(false)},
	} {
		_, err := svc.UpdateSLAPolicy(context.Background(), def.ID().String(), tenantID.String(), in)
		if !errors.Is(err, sladom.ErrDefaultProtected) {
			t.Errorf("%s: want ErrDefaultProtected, got %v", name, err)
		}
	}
	if !def.IsDefault() || !def.IsActive() {
		t.Error("default policy was modified")
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
	input.EscalationEnabled = slaBoolPtr(true)

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

	policy, err := svc.GetSLAPolicy(context.Background(), tenantID.String(), existing.ID().String())
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

	_, err := svc.GetSLAPolicy(context.Background(), shared.NewID().String(), "not-a-uuid")
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

	_, err := svc.GetSLAPolicy(context.Background(), shared.NewID().String(), shared.NewID().String())
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

// TestUpdateSLAPolicy_BlankTenantRejected proves the ownership check fails
// closed: a blank tenant must be rejected, never skip the IDOR check.
func TestUpdateSLAPolicy_BlankTenantRejected(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	tenantID := shared.NewID()
	existing := makeTestPolicy(tenantID, "My Policy", false)
	repo.policies[existing.ID().String()] = existing

	_, err := svc.UpdateSLAPolicy(context.Background(), existing.ID().String(), "", sla.UpdatePolicyInput{})
	if err == nil {
		t.Fatal("expected error for blank tenant")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation for blank tenant, got %v", err)
	}
}

// TestGetSLAPolicy_ForeignTenant proves a policy owned by another tenant is not
// returned (tenant scoping enforced in the query via GetByTenantAndID).
func TestGetSLAPolicy_ForeignTenant(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	ownerTenantID := shared.NewID()
	attackerTenantID := shared.NewID()
	existing := makeTestPolicy(ownerTenantID, "Owner Policy", false)
	repo.policies[existing.ID().String()] = existing

	_, err := svc.GetSLAPolicy(context.Background(), attackerTenantID.String(), existing.ID().String())
	if err == nil {
		t.Fatal("expected error for foreign tenant")
	}
	if !errors.Is(err, sladom.ErrNotFound) {
		t.Errorf("expected ErrNotFound for foreign tenant, got %v", err)
	}
}

// TestGetSLAPolicy_BlankTenantRejected proves a blank tenant is rejected.
func TestGetSLAPolicy_BlankTenantRejected(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	_, err := svc.GetSLAPolicy(context.Background(), "", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for blank tenant")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation for blank tenant, got %v", err)
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
	if !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, sladom.ErrNotFound) {
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
	if !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, sladom.ErrNotFound) {
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
	if !errors.Is(err, sladom.ErrDefaultProtected) {
		t.Errorf("expected ErrDefaultProtected, got %v", err)
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

func TestCreateSLAPolicy_PriorityDays(t *testing.T) {
	svc := newTestSLAService(newMockSLARepo())
	input := validSLACreateInput(shared.NewID().String())
	input.P0Days = slaIntPtr(1)
	input.P2Days = slaIntPtr(10)
	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if policy.P0Days() != 1 || policy.P1Days() != sladom.DefaultPriorityDays["P1"] || policy.P2Days() != 10 {
		t.Fatalf("priority days = %d/%d/%d, want 1/default/10", policy.P0Days(), policy.P1Days(), policy.P2Days())
	}

	bad := validSLACreateInput(shared.NewID().String())
	bad.P0Days = slaIntPtr(40) // longer than the P1 default
	if _, err := svc.CreateSLAPolicy(context.Background(), bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("P0 longer than P1 = %v, want validation error", err)
	}
}

func TestUpdateSLAPolicy_PriorityDaysPartial(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()
	created, err := svc.CreateSLAPolicy(context.Background(), validSLACreateInput(tenantID.String()))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateSLAPolicy(context.Background(), created.ID().String(), tenantID.String(),
		sla.UpdatePolicyInput{P3Days: slaIntPtr(60)})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.P3Days() != 60 || updated.P0Days() != sladom.DefaultPriorityDays["P0"] {
		t.Fatalf("P0/P3 = %d/%d, want default/60", updated.P0Days(), updated.P3Days())
	}
	if _, err := svc.UpdateSLAPolicy(context.Background(), created.ID().String(), tenantID.String(),
		sla.UpdatePolicyInput{P1Days: slaIntPtr(1), P0Days: slaIntPtr(2)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("P0 > P1 update = %v, want validation error", err)
	}
}

func TestCreateSLAPolicy_EscalationDefaultsOn(t *testing.T) {
	svc := newTestSLAService(newMockSLARepo())
	input := validSLACreateInput(shared.NewID().String())
	input.EscalationEnabled = nil
	policy, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.EscalationEnabled() {
		t.Fatal("escalation omitted on create must default to on")
	}
}

// Informational findings get no SLA by default: no policy, a fresh default
// policy, any priority class. The applier therefore leaves sla_deadline NULL.
func TestCalculateSLADeadlineForPriority_InformationalNoSLA(t *testing.T) {
	detectedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tenantID := shared.NewID()

	// No policy configured.
	svc := newTestSLAService(newMockSLARepo())
	for _, sev := range []vulnerability.Severity{vulnerability.SeverityInfo, vulnerability.SeverityNone} {
		for _, class := range []string{"", "P0", "P3"} {
			d, err := svc.CalculateSLADeadlineForPriority(context.Background(), tenantID.String(), "", class, sev, detectedAt)
			if err != nil || !d.IsZero() {
				t.Errorf("no policy, %s/%q: deadline=%v err=%v, want no deadline", sev, class, d, err)
			}
		}
	}
	// A low finding still gets one.
	if d, _ := svc.CalculateSLADeadlineForPriority(context.Background(), tenantID.String(), "", "P3", vulnerability.SeverityLow, detectedAt); d.IsZero() {
		t.Error("low finding got no deadline")
	}
}

func TestCreateSLAPolicy_InfoNoSLAAccepted(t *testing.T) {
	svc := newTestSLAService(newMockSLARepo())
	input := validSLACreateInput(shared.NewID().String())
	input.InfoDays = 0
	p, err := svc.CreateSLAPolicy(context.Background(), input)
	if err != nil {
		t.Fatalf("info days 0 rejected: %v", err)
	}
	if p.InformationalHasSLA() {
		t.Error("policy with info days 0 gives informational findings an SLA")
	}
	// A positive info window still has to be >= low.
	input.InfoDays = 30
	if _, err := svc.CreateSLAPolicy(context.Background(), input); err == nil {
		t.Error("info days 30 < low days 60 accepted")
	}
}

func TestCreateSLAPolicy_RejectsOutOfRangeWindows(t *testing.T) {
	svc := newTestSLAService(newMockSLARepo())
	in := validSLACreateInput(shared.NewID().String())
	in.LowDays = 400 // beyond the 365-day maximum
	in.InfoDays = 0
	if _, err := svc.CreateSLAPolicy(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("400-day window accepted: %v", err)
	}
}
