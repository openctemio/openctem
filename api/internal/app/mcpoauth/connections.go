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

// ListAllClients lists every client with usage counts. Platform admin
// console only (console session); no tenant data.
func (s *Service) ListAllClients(ctx context.Context) ([]mcpoauth.ClientUsage, error) {
	store, err := s.connectionStore()
	if err != nil {
		return nil, err
	}
	return store.ListClientsForPlatform(ctx, s.now())
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
