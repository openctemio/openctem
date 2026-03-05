package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Group Repository
// =============================================================================

// MockGroupRepository implements group.Repository for testing.
// Only the methods needed by GroupSyncService are implemented; the rest are stubs.
type MockGroupRepository struct {
	groups    map[string]*group.Group
	createErr error
}

func NewMockGroupRepository() *MockGroupRepository {
	return &MockGroupRepository{
		groups: make(map[string]*group.Group),
	}
}

func (m *MockGroupRepository) Create(_ context.Context, g *group.Group) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.groups[g.ID().String()] = g
	return nil
}

func (m *MockGroupRepository) GetByID(_ context.Context, id shared.ID) (*group.Group, error) {
	if g, ok := m.groups[id.String()]; ok {
		return g, nil
	}
	return nil, shared.ErrNotFound
}

func (m *MockGroupRepository) GetBySlug(_ context.Context, _ shared.ID, _ string) (*group.Group, error) {
	return nil, shared.ErrNotFound
}

func (m *MockGroupRepository) Update(_ context.Context, _ *group.Group) error {
	return nil
}

func (m *MockGroupRepository) Delete(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *MockGroupRepository) List(_ context.Context, _ shared.ID, _ group.ListFilter) ([]*group.Group, error) {
	return nil, nil
}

func (m *MockGroupRepository) Count(_ context.Context, _ shared.ID, _ group.ListFilter) (int64, error) {
	return 0, nil
}

func (m *MockGroupRepository) ExistsBySlug(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *MockGroupRepository) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}

func (m *MockGroupRepository) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, shared.ErrNotFound
}

func (m *MockGroupRepository) AddMember(_ context.Context, _ *group.Member) error {
	return nil
}

func (m *MockGroupRepository) GetMember(_ context.Context, _, _ shared.ID) (*group.Member, error) {
	return nil, shared.ErrNotFound
}

func (m *MockGroupRepository) UpdateMember(_ context.Context, _ *group.Member) error {
	return nil
}

func (m *MockGroupRepository) RemoveMember(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *MockGroupRepository) ListMembers(_ context.Context, _ shared.ID) ([]*group.Member, error) {
	return nil, nil
}

func (m *MockGroupRepository) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*group.MemberWithUser, error) {
	return nil, nil
}

func (m *MockGroupRepository) CountMembers(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *MockGroupRepository) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}

func (m *MockGroupRepository) IsMember(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}

func (m *MockGroupRepository) ListGroupsByUser(_ context.Context, _, _ shared.ID) ([]*group.GroupWithRole, error) {
	return nil, nil
}

func (m *MockGroupRepository) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *MockGroupRepository) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}

func (m *MockGroupRepository) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *MockGroupRepository) ListPermissionSetIDs(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *MockGroupRepository) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Tests for GroupSyncService
// =============================================================================

// TestGroupSyncService_SyncFromProvider tests the SyncFromProvider method.
//
// Run with: go test -v ./internal/app/ -run TestGroupSyncService_SyncFromProvider
func TestGroupSyncService_SyncFromProvider(t *testing.T) {
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("ValidProvider_NotImplemented", func(t *testing.T) {
		providers := []struct {
			name     string
			provider string
		}{
			{"GitHub", "github"},
			{"GitLab", "gitlab"},
			{"AzureAD", "azure_ad"},
			{"Okta", "okta"},
		}

		for _, tc := range providers {
			t.Run(tc.name, func(t *testing.T) {
				repo := NewMockGroupRepository()
				service := NewGroupSyncService(repo, log)

				err := service.SyncFromProvider(context.Background(), tenantID, tc.provider, map[string]interface{}{
					"token": "test-token",
				})

				// Valid provider is accepted but sync is not yet implemented
				require.Error(t, err)
				assert.ErrorIs(t, err, shared.ErrNotImplemented)
			})
		}
	})

	t.Run("InvalidProvider_ReturnsError", func(t *testing.T) {
		repo := NewMockGroupRepository()
		service := NewGroupSyncService(repo, log)

		err := service.SyncFromProvider(context.Background(), tenantID, "invalid_provider", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, shared.ErrValidation)
		assert.Contains(t, err.Error(), "unsupported provider")
	})

	t.Run("EmptyProvider_ReturnsError", func(t *testing.T) {
		repo := NewMockGroupRepository()
		service := NewGroupSyncService(repo, log)

		err := service.SyncFromProvider(context.Background(), tenantID, "", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, shared.ErrValidation)
	})

	t.Run("NilConfig_NotImplemented", func(t *testing.T) {
		repo := NewMockGroupRepository()
		service := NewGroupSyncService(repo, log)

		// Should not panic with nil config for valid provider
		err := service.SyncFromProvider(context.Background(), tenantID, "github", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, shared.ErrNotImplemented)
	})
}

// TestGroupSyncService_SyncAll tests the SyncAll method.
//
// Run with: go test -v ./internal/app/ -run TestGroupSyncService_SyncAll
func TestGroupSyncService_SyncAll(t *testing.T) {
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("SyncAll_NotImplemented", func(t *testing.T) {
		repo := NewMockGroupRepository()
		service := NewGroupSyncService(repo, log)

		err := service.SyncAll(context.Background(), tenantID)

		require.Error(t, err)
		assert.ErrorIs(t, err, shared.ErrNotImplemented)
	})

	t.Run("SyncAll_MultipleCallsConsistent", func(t *testing.T) {
		repo := NewMockGroupRepository()
		service := NewGroupSyncService(repo, log)

		// Multiple calls should consistently return not implemented
		for range 3 {
			err := service.SyncAll(context.Background(), tenantID)
			require.Error(t, err)
			assert.ErrorIs(t, err, shared.ErrNotImplemented)
		}
	})
}
