package cirun

// A trust configuration adds the repositories it trusts to the organization's
// scope (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI
// trusts"). The scope service owns the entries; this file tells it what each
// trust claims and which verified runs it saw. A scope failure never fails a
// trust change or a CI job: it is logged and audited, and the next change or
// run of the trust repairs it.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeLinker keeps a trust's repository scope entries (*scope.Service).
type ScopeLinker interface {
	SyncCITrust(ctx context.Context, tenantID shared.ID, in scopeapp.CITrustScope) ([]scopedom.CITrustSyncOutcome, error)
	CITrustSeen(ctx context.Context, tenantID shared.ID, in scopeapp.CITrustScope, ev scopedom.CITrustEvidence) error
	CITrustLinks(ctx context.Context, tenantID, trustID shared.ID) ([]scopedom.CITrustLink, error)
}

// SetScopeLinker wires the scope service. Without it trusts manage no scope.
func (s *Service) SetScopeLinker(l ScopeLinker) { s.scope = l }

// TrustScope lists a trust's repository scope links (patterns, entries,
// evidence of a verified run).
func (s *Service) TrustScope(ctx context.Context, tenantID, id shared.ID) ([]scopedom.CITrustLink, error) {
	if s.scope == nil {
		return nil, nil
	}
	return s.scope.CITrustLinks(ctx, tenantID, id)
}

// syncScope brings the trust's scope entries in line with it (none for a
// deleted trust: c is the trust as it was, wantNone retires everything) and
// audits what changed.
func (s *Service) syncScope(ctx context.Context, tenantID shared.ID, c *cirun.TrustConfig, wantNone bool, a Actor) {
	if s.scope == nil || c == nil {
		return
	}
	in := scopeapp.CITrustScope{TrustID: c.ID, TrustName: c.Name, By: a.UserID}
	if !wantNone {
		in.Patterns = cirun.ScopePatterns(c)
	}
	out, err := s.scope.SyncCITrust(ctx, tenantID, in)
	if err != nil {
		s.log.Warn("ci trust scope not synced", "trust_config_id", c.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	var changed, refused []string
	for _, o := range out {
		switch o.Action {
		case scopedom.CITrustCreated, scopedom.CITrustLinked, scopedom.CITrustRetired:
			changed = append(changed, o.Action+" "+o.Pattern)
		case scopedom.CITrustRefused:
			refused = append(refused, fmt.Sprintf("%s (%s)", o.Pattern, refusalText(o.Err)))
		}
	}
	if len(changed) == 0 && len(refused) == 0 {
		return
	}
	msg := fmt.Sprintf("CI trust configuration %q scope: %s", c.Name, strings.Join(changed, ", "))
	if len(refused) > 0 {
		msg += "; refused: " + strings.Join(refused, ", ")
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCITrustConfigUpdated, auditdom.ResourceTypeCITrustConfig, c.ID.String()).
		WithResourceName(c.Name).
		WithMessage(msg).
		WithMetadata("scope_changes", changed).
		WithMetadata("scope_refused", refused))
}

func refusalText(err error) string {
	if err == nil {
		return ""
	}
	return logger.SanitizeError(err)
}

// scopeSeen records a verified, tenant-bound run as evidence on the trust's
// scope entries (best effort).
func (s *Service) scopeSeen(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims, out *ExchangeOutput) {
	if s.scope == nil || cfg == nil || out == nil || out.Run == nil {
		return
	}
	patterns := cirun.ScopePatterns(cfg)
	if len(patterns) == 0 {
		return
	}
	ev := scopedom.CITrustEvidence{RunID: out.Run.ID, Repository: c.CanonicalRepository(), OwnerID: c.OwnerID, At: s.now().UTC()}
	if err := s.scope.CITrustSeen(ctx, tenantID, scopeapp.CITrustScope{TrustID: cfg.ID, TrustName: cfg.Name, Patterns: patterns}, ev); err != nil {
		s.log.Warn("ci trust scope evidence not recorded", "trust_config_id", cfg.ID.String(), "error", logger.SanitizeError(err))
	}
}
