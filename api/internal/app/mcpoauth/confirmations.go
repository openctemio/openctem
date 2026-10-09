package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Write-tool confirmation (RFC-062 §10). A write tool called through an MCP
// connection does nothing until the person the connection belongs to
// approves the exact action in the OpenCTEM web UI, outside the AI
// application: a compromised or prompt-injected agent can answer an
// in-client prompt, but it cannot sign in as the person. The confirmation
// is bound to the connection, the tool and a digest of the arguments, lives
// five minutes and is used once.

// ConfirmPagePath is the web page that shows a confirmation.
const ConfirmPagePath = "/mcp/confirm/"

// ErrConfirmationsUnavailable means the service was built without the store.
var ErrConfirmationsUnavailable = errors.New("write confirmations are not available")

const maxSummaryLen = 12000

// ArgsDigest is the SHA-256 of the canonical JSON of a tool's arguments
// without confirmation_id (map keys are sorted by encoding/json).
func ArgsDigest(tool string, args map[string]any) string {
	clean := make(map[string]any, len(args))
	for k, v := range args {
		if k != "confirmation_id" {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(map[string]any{"tool": tool, "args": clean})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// PendingConfirmation is what a write tool returns before it runs.
type PendingConfirmation struct {
	ID  string
	URL string
}

// RequestConfirmation records a write action waiting for the person's
// approval and returns where to approve it. Only a connection made by a
// person (an OAuth principal) can ask: there is nobody to confirm for an
// API key.
func (s *Service) RequestConfirmation(ctx context.Context, p *Principal, tool, digest, summary string, actor Actor) (*PendingConfirmation, error) {
	if s.confirmations == nil {
		return nil, ErrConfirmationsUnavailable
	}
	if p == nil {
		return nil, mcpoauth.ErrConfirmationRequired
	}
	if len(summary) > maxSummaryLen {
		summary = summary[:maxSummaryLen]
	}
	now := s.now()
	c := &mcpoauth.Confirmation{
		ID:         shared.NewID(),
		TenantID:   shared.MustIDFromString(p.TenantID),
		GrantID:    shared.MustIDFromString(p.GrantID),
		UserID:     shared.MustIDFromString(p.UserID),
		Tool:       tool,
		ArgsDigest: digest,
		Summary:    summary,
		CreatedAt:  now,
		ExpiresAt:  now.Add(mcpoauth.ConfirmationTTL),
	}
	if err := s.confirmations.CreateConfirmation(ctx, c); err != nil {
		return nil, err
	}
	s.logAudit(ctx, p.TenantID, p.UserID, actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPActionRequested, auditdom.ResourceTypeMCPGrant, c.ID.String()).
			WithResourceName(tool).
			WithMessage(p.ClientName+" asked to run "+tool+"; waiting for confirmation").
			WithMetadata("tool", tool).
			WithMetadata("grant_id", p.GrantID).
			WithMetadata("client_id", p.ClientID))
	return &PendingConfirmation{ID: c.ID.String(), URL: s.endpoints.Issuer + ConfirmPagePath + c.ID.String()}, nil
}

// UseConfirmation consumes the approved confirmation of this exact action;
// anything else is mcpoauth.ErrConfirmationRequired.
func (s *Service) UseConfirmation(ctx context.Context, p *Principal, id, tool, digest string) error {
	if s.confirmations == nil {
		return ErrConfirmationsUnavailable
	}
	cid, err := shared.IDFromString(id)
	if p == nil || err != nil {
		return mcpoauth.ErrConfirmationRequired
	}
	return s.confirmations.UseConfirmation(ctx, shared.MustIDFromString(p.TenantID), shared.MustIDFromString(p.GrantID),
		cid, tool, digest, s.now())
}

// ConfirmationView is a confirmation as the web page shows it.
type ConfirmationView struct {
	ID         string
	Tool       string
	Summary    string
	ClientName string
	Status     mcpoauth.ConfirmationStatus
	Expired    bool
	ExpiresAt  time.Time
}

// GetConfirmation returns a confirmation of the signed-in user in the
// session's organization; anyone else's is not found.
func (s *Service) GetConfirmation(ctx context.Context, tenantID, userID, id shared.ID) (*ConfirmationView, error) {
	if s.confirmations == nil {
		return nil, ErrConfirmationsUnavailable
	}
	c, err := s.confirmations.GetConfirmation(ctx, tenantID, userID, id)
	if err != nil {
		return nil, err
	}
	return &ConfirmationView{
		ID: c.ID.String(), Tool: c.Tool, Summary: c.Summary, ClientName: c.ClientName, Status: c.Status,
		Expired: !s.now().Before(c.ExpiresAt), ExpiresAt: c.ExpiresAt,
	}, nil
}

// DecideConfirmation records the person's approval or refusal.
func (s *Service) DecideConfirmation(ctx context.Context, tenantID, userID, id shared.ID, approve bool, actor Actor) error {
	if s.confirmations == nil {
		return ErrConfirmationsUnavailable
	}
	if err := s.confirmations.DecideConfirmation(ctx, tenantID, userID, id, approve, s.now()); err != nil {
		return err
	}
	action, msg := auditdom.ActionMCPActionRefused, "MCP write action refused"
	if approve {
		action, msg = auditdom.ActionMCPActionConfirmed, "MCP write action confirmed"
	}
	s.logAudit(ctx, tenantID.String(), userID.String(), actor,
		auditapp.NewSuccessEvent(action, auditdom.ResourceTypeMCPGrant, id.String()).WithMessage(msg))
	return nil
}
