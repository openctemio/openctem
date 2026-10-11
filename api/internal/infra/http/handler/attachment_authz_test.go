package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// mockAccessChecker lets each test decide whether finding/campaign access is
// allowed, and records which method was consulted.
type mockAccessChecker struct {
	findingErr     error
	campaignErr    error
	findingCalled  bool
	campaignCalled bool

	findingWriteErr     error
	campaignWriteErr    error
	findingWriteCalled  bool
	campaignWriteCalled bool
}

func (m *mockAccessChecker) CheckFindingAccess(_ context.Context, _, _, _ string, _ bool) error {
	m.findingCalled = true
	return m.findingErr
}

func (m *mockAccessChecker) CheckCampaignAccess(_ context.Context, _, _, _ string, _ bool) error {
	m.campaignCalled = true
	return m.campaignErr
}

func (m *mockAccessChecker) CheckFindingEvidenceWrite(_ context.Context, _, _, _ string, _ bool) error {
	m.findingWriteCalled = true
	return m.findingWriteErr
}

func (m *mockAccessChecker) CheckCampaignEvidenceWrite(_ context.Context, _, _, _ string, _ bool) error {
	m.campaignWriteCalled = true
	return m.campaignWriteErr
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

// Removing evidence uses the write checks, never the read (membership) ones:
// an observer or a tester on someone else's finding can read the evidence but
// not delete it.
func TestAuthorizeAttachmentWrite(t *testing.T) {
	tenant := shared.NewID()
	owner := shared.NewID()
	other := shared.NewID()
	mk := func(ctxType, ctxID string) *attachment.Attachment {
		return attachment.NewAttachment(tenant, "f.png", "image/png", 10, "key", owner, ctxType, ctxID)
	}
	forbidden := errors.Join(shared.ErrForbidden, errors.New("observer"))

	tests := []struct {
		name         string
		att          *attachment.Attachment
		userID       string
		isAdmin      bool
		checker      *mockAccessChecker
		wantErr      bool
		wantFinding  bool
		wantCampaign bool
	}{
		{"finding: read access is not enough", mk("finding", shared.NewID().String()), other.String(), false,
			&mockAccessChecker{findingWriteErr: forbidden}, true, true, false},
		{"retest: write check consulted", mk("retest", shared.NewID().String()), other.String(), false,
			&mockAccessChecker{}, false, true, false},
		{"campaign: write check consulted", mk("campaign", shared.NewID().String()), other.String(), false,
			&mockAccessChecker{campaignWriteErr: forbidden}, true, false, true},
		{"no context: uploader may delete", mk("", ""), owner.String(), false,
			&mockAccessChecker{}, false, false, false},
		{"no context: others may not", mk("", ""), other.String(), false,
			&mockAccessChecker{}, true, false, false},
		{"admin bypasses", mk("finding", shared.NewID().String()), other.String(), true,
			&mockAccessChecker{findingWriteErr: forbidden}, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &AttachmentHandler{}
			h.SetAccessChecker(tc.checker)
			req := httptest.NewRequest("DELETE", "/x", nil)
			ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, tc.userID)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, tc.isAdmin)
			req = req.WithContext(ctx)

			err := h.authorizeAttachmentWrite(req, tc.att)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.checker.findingCalled || tc.checker.campaignCalled {
				t.Error("a read check was used for a delete")
			}
			if tc.wantFinding != tc.checker.findingWriteCalled {
				t.Errorf("CheckFindingEvidenceWrite consulted=%v, want %v", tc.checker.findingWriteCalled, tc.wantFinding)
			}
			if tc.wantCampaign != tc.checker.campaignWriteCalled {
				t.Errorf("CheckCampaignEvidenceWrite consulted=%v, want %v", tc.checker.campaignWriteCalled, tc.wantCampaign)
			}
		})
	}
}

func TestWriteAttachmentAccessError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeAttachmentAccessError(rec, errors.Join(shared.ErrForbidden, errors.New("x")))
	if rec.Code != 403 {
		t.Fatalf("forbidden → %d, want 403", rec.Code)
	}
	rec = httptest.NewRecorder()
	writeAttachmentAccessError(rec, errors.New("not a member"))
	if rec.Code != 404 {
		t.Fatalf("non-member → %d, want 404", rec.Code)
	}
}
