// Package toolaudit writes the tenant audit entry an operator command leaves
// behind. The refingerprint and repomerge commands change every tenant's data
// outside any request, so without an entry an organization cannot tell why its
// findings merged or changed ids. One entry per affected tenant per run, in
// that tenant only: the row carries the tenant id, never another tenant's data.
package toolaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Writer stores an audit entry (the audit log repository).
type Writer interface {
	Create(ctx context.Context, log *audit.AuditLog) error
}

// Event is one command run's effect on one tenant.
type Event struct {
	TenantID     shared.ID
	Action       audit.Action
	ResourceType audit.ResourceType
	// Actor names the command (the entry has no user): "refingerprint" or "repomerge".
	Actor  string
	RunID  string
	Counts map[string]int
}

// NewRunID returns the id shared by the entries of one command run.
func NewRunID() string { return shared.NewID().String() }

// Record writes the entry for one tenant.
func Record(ctx context.Context, w Writer, e Event) error {
	if e.TenantID.IsZero() {
		return fmt.Errorf("toolaudit: a tenant is required")
	}
	entry, err := audit.NewAuditLog(e.Action, e.ResourceType, e.TenantID.String(), audit.ResultSuccess)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(e.Counts))
	for k := range e.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		entry.WithMetadata(k, e.Counts[k])
		parts = append(parts, fmt.Sprintf("%s %d", k, e.Counts[k]))
	}
	entry.WithTenantID(e.TenantID).
		WithActorUserAgent(e.Actor).
		WithMetadata("run_id", e.RunID).
		WithMetadata("actor", e.Actor).
		WithMessage(fmt.Sprintf("%s: %s (run %s)", e.Actor, strings.Join(parts, ", "), e.RunID))
	if err := w.Create(ctx, entry); err != nil {
		return fmt.Errorf("audit %s for tenant %s: %w", e.Action, e.TenantID, err)
	}
	return nil
}
