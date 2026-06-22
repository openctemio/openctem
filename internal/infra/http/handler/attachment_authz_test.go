package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
)

// mockAccessChecker lets each test decide whether finding/campaign access is
// allowed, and records which method was consulted.
type mockAccessChecker struct {
	findingErr     error
	campaignErr    error
	findingCalled  bool
	campaignCalled bool
}

func (m *mockAccessChecker) CheckFindingAccess(_ context.Context, _, _, _ string, _ bool) error {
	m.findingCalled = true
	return m.findingErr
}

func (m *mockAccessChecker) CheckCampaignAccess(_ context.Context, _, _, _ string, _ bool) error {
	m.campaignCalled = true
	return m.campaignErr
}

func TestAuthorizeAttachment(t *testing.T) {
	tenant := shared.NewID()
	owner := shared.NewID()
	other := shared.NewID()

	mk := func(ctxType, ctxID string, uploadedBy shared.ID) *attachment.Attachment {
		return attachment.NewAttachment(tenant, "f.png", "image/png", 10, "key", uploadedBy, ctxType, ctxID)
	}

	tests := []struct {
		name        string
		att         *attachment.Attachment
		userID      string
		isAdmin     bool
		checker     *mockAccessChecker
		wantErr     bool
		wantFinding bool // CheckFindingAccess consulted
		wantCamp    bool // CheckCampaignAccess consulted
	}{
		{
			name:        "finding context delegates to CheckFindingAccess (allowed)",
			att:         mk("finding", shared.NewID().String(), owner),
			userID:      other.String(),
			checker:     &mockAccessChecker{findingErr: nil},
			wantErr:     false,
			wantFinding: true,
		},
		{
			name:        "finding context delegates to CheckFindingAccess (denied)",
			att:         mk("finding", shared.NewID().String(), owner),
			userID:      other.String(),
			checker:     &mockAccessChecker{findingErr: errors.New("not a member")},
			wantErr:     true,
			wantFinding: true,
		},
		{
			name:     "campaign context delegates to CheckCampaignAccess (denied) — was the IDOR hole",
			att:      mk("campaign", shared.NewID().String(), owner),
			userID:   other.String(),
			checker:  &mockAccessChecker{campaignErr: errors.New("not a member")},
			wantErr:  true,
			wantCamp: true,
		},
		{
			name:     "campaign context allowed for member",
			att:      mk("campaign", shared.NewID().String(), owner),
			userID:   other.String(),
			checker:  &mockAccessChecker{campaignErr: nil},
			wantErr:  false,
			wantCamp: true,
		},
		{
			name:    "no context: denied for non-uploader — was the IDOR hole",
			att:     mk("", "", owner),
			userID:  other.String(),
			checker: &mockAccessChecker{},
			wantErr: true,
		},
		{
			name:    "no context: allowed for uploader",
			att:     mk("", "", owner),
			userID:  owner.String(),
			checker: &mockAccessChecker{},
			wantErr: false,
		},
		{
			name:    "admin bypasses all checks",
			att:     mk("campaign", shared.NewID().String(), owner),
			userID:  other.String(),
			isAdmin: true,
			checker: &mockAccessChecker{campaignErr: errors.New("not a member")},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &AttachmentHandler{}
			h.SetAccessChecker(tc.checker)
			req := httptest.NewRequest("GET", "/x", nil)
			ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, tc.userID)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, tc.isAdmin)
			req = req.WithContext(ctx)

			err := h.authorizeAttachment(req, tc.att)
			if tc.wantErr && err == nil {
				t.Fatalf("expected access denied, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected access allowed, got %v", err)
			}
			if tc.wantFinding != tc.checker.findingCalled {
				t.Errorf("CheckFindingAccess consulted=%v, want %v", tc.checker.findingCalled, tc.wantFinding)
			}
			if tc.wantCamp != tc.checker.campaignCalled {
				t.Errorf("CheckCampaignAccess consulted=%v, want %v", tc.checker.campaignCalled, tc.wantCamp)
			}
		})
	}
}

// When no checker is wired (tests/dev), behavior is permissive (preserved).
func TestAuthorizeAttachment_NoCheckerIsPermissive(t *testing.T) {
	h := &AttachmentHandler{}
	att := attachment.NewAttachment(shared.NewID(), "f", "image/png", 1, "k", shared.NewID(), "campaign", shared.NewID().String())
	req := httptest.NewRequest("GET", "/x", nil)
	if err := h.authorizeAttachment(req, att); err != nil {
		t.Fatalf("expected permissive nil when no checker wired, got %v", err)
	}
}
