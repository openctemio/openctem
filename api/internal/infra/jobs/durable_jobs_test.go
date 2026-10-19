package jobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type sentInvite struct {
	to, token, tenant string
	left              time.Duration
}

type fakeSender struct{ sent []sentInvite }

func (f *fakeSender) SendTeamInvitationEmail(_ context.Context, to, _, _, token string, left time.Duration, tenantID ...string) error {
	f.sent = append(f.sent, sentInvite{to: to, token: token, tenant: tenantID[0], left: left})
	return nil
}

func testCipher(t *testing.T) crypto.Encryptor {
	t.Helper()
	c, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The raw link token is sealed in the job (the database otherwise holds only
// its hash) and opened only by the handler, which sends to the job's tenant.
func TestInvitationEmailJob_SealedAndSent(t *testing.T) {
	enc := testCipher(t)
	tenantID, invitationID := shared.NewID(), shared.NewID()
	job, err := NewInvitationEmailJobs(enc).TeamInvitationJob(tenant.TeamInvitationJobPayload{
		RecipientEmail: "invitee@example.com", InviterName: "A", TeamName: "T", Token: "raw-token-123",
		ExpiresIn: time.Hour, InvitationID: invitationID.String(), TenantID: tenantID.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Kind != durablejob.KindInvitationEmail || job.TenantID != tenantID || job.SubjectID != invitationID {
		t.Fatalf("job = %+v", job)
	}
	if strings.Contains(job.Payload, "raw-token-123") || strings.Contains(job.Payload, "invitee@example.com") {
		t.Fatal("payload is not sealed")
	}

	sender := &fakeSender{}
	if err := InvitationEmailHandler(sender, enc)(context.Background(), durablejob.Claimed{Job: job}); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || sender.sent[0].token != "raw-token-123" || sender.sent[0].tenant != tenantID.String() ||
		sender.sent[0].left <= 0 || sender.sent[0].left > time.Hour {
		t.Fatalf("sent %+v", sender.sent)
	}
}

// An expired invitation, or a payload sealed under another key, is given up.
func TestInvitationEmailJob_PermanentFailures(t *testing.T) {
	enc := testCipher(t)
	job, err := NewInvitationEmailJobs(enc).TeamInvitationJob(tenant.TeamInvitationJobPayload{
		RecipientEmail: "invitee@example.com", Token: "t", ExpiresIn: -time.Minute,
		InvitationID: shared.NewID().String(), TenantID: shared.NewID().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{}
	h := InvitationEmailHandler(sender, enc)
	var perm interface{ Permanent() bool }
	if err := h(context.Background(), durablejob.Claimed{Job: job}); !errors.As(err, &perm) || !perm.Permanent() {
		t.Fatalf("expired invitation: %v", err)
	}
	other, _ := crypto.NewCipher([]byte("fedcba9876543210fedcba9876543210"))
	if err := InvitationEmailHandler(sender, other)(context.Background(), durablejob.Claimed{Job: job}); !errors.As(err, &perm) {
		t.Fatalf("foreign key payload: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent %+v", sender.sent)
	}
}

type fakeSyncer struct{ tenant, finding shared.ID }

func (f *fakeSyncer) SyncFindingStatus(_ context.Context, tenantID, findingID shared.ID) error {
	f.tenant, f.finding = tenantID, findingID
	return nil
}

func TestStatusSyncHandler_UsesTheJobsTenant(t *testing.T) {
	s := &fakeSyncer{}
	j := durablejob.Claimed{Job: durablejob.Job{Kind: durablejob.KindJiraStatusSync, TenantID: shared.NewID(), SubjectID: shared.NewID()}}
	if err := StatusSyncHandler(s)(context.Background(), j); err != nil || s.tenant != j.TenantID || s.finding != j.SubjectID {
		t.Fatalf("synced %s/%s (%v)", s.tenant, s.finding, err)
	}
}
