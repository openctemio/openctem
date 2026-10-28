package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Connected applications (RFC-062 §12): what a person, an organization
// administrator and a platform administrator see and revoke.

// ConnectionView is one connection as the pages show it.
type ConnectionView struct {
	ID         string
	ClientName string
	ClientID   string
	ClientKind mcpoauth.ClientKind
	ClientHost string
	UserID     string
	UserName   string
	UserEmail  string
	Scopes     []mcpoauth.Scope
	CreatedAt  time.Time
	LastUsedAt *time.Time
	LastUsedIP string
	ExpiresAt  time.Time
	// FullData: the connection may read all organization data (while its
	// person keeps a full-data role).
	FullData bool
}

// ErrConnectionsUnavailable means the service was built without the
// connections store.
var ErrConnectionsUnavailable = errors.New("mcp connections are not available")

func (s *Service) connectionStore() (mcpoauth.ConnectionRepository, error) {
	if s.connections == nil {
		return nil, ErrConnectionsUnavailable
	}
	return s.connections, nil
}

// ListConnections returns the organization's active connections; only the
// caller's own when userID is set.
func (s *Service) ListConnections(ctx context.Context, tenantID shared.ID, userID *shared.ID) ([]ConnectionView, error) {
	store, err := s.connectionStore()
	if err != nil {
		return nil, err
	}
	list, err := store.ListConnections(ctx, tenantID, userID, s.now())
	if err != nil {
		return nil, err
	}
	out := make([]ConnectionView, 0, len(list))
	for _, c := range list {
		g := c.Grant
		out = append(out, ConnectionView{
			ID: g.ID.String(), ClientName: g.Client.Name, ClientID: g.Client.ClientID, ClientKind: g.Client.Kind,
			ClientHost: clientHost(g.Client), UserID: g.UserID.String(), UserName: c.UserName, UserEmail: c.UserEmail,
			Scopes: g.Scopes, CreatedAt: g.CreatedAt, LastUsedAt: g.LastUsedAt, LastUsedIP: g.LastUsedIP, ExpiresAt: g.ExpiresAt,
			FullData: g.FullData,
		})
	}
	return out, nil
}

// RevokeConnection ends a connection. A person may end only their own
// (asAdmin false); an organization administrator any in the organization.
// Another person's connection, or another organization's, is not found.
func (s *Service) RevokeConnection(ctx context.Context, tenantID, grantID, actorID shared.ID, asAdmin bool, actor Actor) error {
	store, err := s.connectionStore()
	if err != nil {
		return err
	}
	g, err := store.GetGrant(ctx, tenantID, grantID)
	if err != nil {
		return err
	}
	if !asAdmin && g.UserID != actorID {
		return mcpoauth.ErrNotFound
	}
	if g.RevokedAt != nil {
		return nil
	}
	reason := mcpoauth.RevokedByUser
	if asAdmin && g.UserID != actorID {
		reason = mcpoauth.RevokedByAdmin
	}
	now := s.now()
	if err := s.repo.RevokeGrant(ctx, tenantID, g.ID, reason, now); err != nil {
		return fmt.Errorf("revoke connection: %w", err)
	}
	s.logAudit(ctx, tenantID.String(), actorID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPGrantRevoked, auditdom.ResourceTypeMCPGrant, g.ID.String()).
			WithResourceName(g.Client.Name).
			WithMessage("MCP connection to "+g.Client.Name+" revoked").
			WithMetadata("client_id", g.Client.ClientID).
			WithMetadata("user_id", g.UserID.String()).
			WithMetadata("reason", reason))
	return nil
}

// ScopeConnection turns a connection that may read all organization data
// back into one that reads only its person's own data scope; the tokens stay
// valid. A person may change only their own (asAdmin false); an organization
// administrator any in the organization. Another person's connection, or
// another organization's, is not found. Narrowing needs no step-up.
func (s *Service) ScopeConnection(ctx context.Context, tenantID, grantID, actorID shared.ID, asAdmin bool, actor Actor) error {
	store, err := s.connectionStore()
	if err != nil {
		return err
	}
	g, err := store.GetGrant(ctx, tenantID, grantID)
	if err != nil {
		return err
	}
	if !asAdmin && g.UserID != actorID {
		return mcpoauth.ErrNotFound
	}
	return s.downgradeGrant(ctx, g, actorID, "user", actor)
}

// downgradeGrant sets a full-data grant back to scoped and audits it. A grant
// that is not full-data is left alone.
func (s *Service) downgradeGrant(ctx context.Context, g *mcpoauth.Grant, actorID shared.ID, reason string, actor Actor) error {
	if !g.FullData || g.RevokedAt != nil {
		return nil
	}
	changed, err := s.repo.SetGrantScoped(ctx, g.TenantID, g.ID)
	if err != nil {
		return fmt.Errorf("scope connection: %w", err)
	}
	if !changed {
		return nil
	}
	s.logAudit(ctx, g.TenantID.String(), actorID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPFullDataRemoved, auditdom.ResourceTypeMCPGrant, g.ID.String()).
			WithResourceName(g.Client.Name).
			WithMessage("MCP connection to "+g.Client.Name+" no longer reads all organization data").
			WithMetadata("client_id", g.Client.ClientID).
			WithMetadata("client_host", clientHost(g.Client)).
			WithMetadata("user_id", g.UserID.String()).
			WithMetadata("reason", reason))
	return nil
}

// RevokeUserGrants ends every connected application of one person in every
// organization, after a credential change (password reset or change, sign-out
// everywhere). It touches only that user and returns how many connections
// ended. No per-organization audit event is written here: the credential
// change itself is audited, and this logs the count.
func (s *Service) RevokeUserGrants(ctx context.Context, userID shared.ID) (int, error) {
	n, err := s.repo.RevokeGrantsByUser(ctx, userID, mcpoauth.RevokedCredentials, s.now())
	if err != nil {
		s.log.Error("mcp oauth: revoke user grants", "user_id", userID.String(), "error", err.Error())
		return 0, err
	}
	if n > 0 {
		s.log.Info("mcp oauth: connected applications revoked after a credential change",
			"user_id", userID.String(), "grants", n)
	}
	return n, nil
}

// ListAllClients lists one page of clients with usage counts, and the total
// matching the filter. Platform admin console only (console session); no
// tenant data.
func (s *Service) ListAllClients(ctx context.Context, f mcpoauth.ClientFilter, limit, offset int) ([]mcpoauth.ClientUsage, int, error) {
	store, err := s.connectionStore()
	if err != nil {
		return nil, 0, err
	}
	return store.ListClientsForPlatform(ctx, f, limit, offset, s.now())
}

// SetClientBlocked blocks or unblocks a client everywhere. The
// console's audit middleware records who did it.
func (s *Service) SetClientBlocked(ctx context.Context, clientRef shared.ID, blocked bool) error {
	store, err := s.connectionStore()
	if err != nil {
		return err
	}
	return store.SetClientBlockedForPlatform(ctx, clientRef, blocked, s.now())
}

// ClientHost is the host of a metadata-document client ("" otherwise).
func ClientHost(c mcpoauth.Client) string { return clientHost(c) }
