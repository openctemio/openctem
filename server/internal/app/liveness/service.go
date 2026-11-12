// Package liveness records what the coverage loop observes about whether
// assets are still there and applies it: liveness states, and for a gone
// asset the close of its open findings as obsolete_asset (never counted as
// fixed), reopened when the asset is seen again
// (docs/architecture/asset-liveness.md).
//
// The pass runs as the platform, per organization, on a schedule. Every
// state change has a state-history row; every finding move has its
// timeline entry and audit row (in the repository), and a pass that changed
// anything writes one summary audit row. A pass that closed findings tells
// the organization's administrators.
package liveness

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/liveness"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Batch bounds how many assets a pass re-decides per kind, and how many
// findings it closes and reopens, per organization. More finish next pass.
const Batch = 1000

// Repository is *postgres.AssetLivenessRepository.
type Repository interface {
	Observe(ctx context.Context, tenantID shared.ID, obs []liveness.AssetObservation, th liveness.Thresholds, now time.Time) (map[shared.ID]liveness.Transition, error)
	Rows(ctx context.Context, tenantID shared.ID, services bool, limit int) ([]liveness.Row, error)
	GoneSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error)
	AddServicesOfGoneHosts(ctx context.Context, tenantID shared.ID) (int, error)
	SetState(ctx context.Context, tenantID, assetID shared.ID, before, after liveness.Evidence) (bool, error)
	TenantsWithLiveness(ctx context.Context) ([]shared.ID, error)
	CloseGone(ctx context.Context, tenantID shared.ID, limit int) (liveness.CloseResult, error)
	ReopenNotGone(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error)
	StateCounts(ctx context.Context, tenantID shared.ID) (map[string]int, error)
	CountOpenFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (open, critical int, err error)
	CountReopenable(ctx context.Context, tenantID shared.ID, stillGone []shared.ID) (int, error)
}

// SettingsReader reads the organization's lifecycle settings (the tenant
// service).
type SettingsReader interface {
	GetAssetLifecycleSettings(ctx context.Context, tenantID string) (*tenantdom.AssetLifecycleSettings, error)
}

// AdminDirectory lists an organization's active owners and administrators.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier sends an in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// Service is the liveness recorder and reconciler.
type Service struct {
	repo     Repository
	settings SettingsReader
	audit    auditapp.EventWriter
	admins   AdminDirectory
	inApp    InAppNotifier
	now      func() time.Time
	logger   *logger.Logger
}

// NewService creates the service. settings and audit may be nil (tests):
// no settings means the defaults (closing off).
func NewService(repo Repository, settings SettingsReader, audit auditapp.EventWriter, log *logger.Logger) *Service {
	return &Service{repo: repo, settings: settings, audit: audit, now: time.Now, logger: log.With("service", "asset-liveness")}
}

// EnableNotifications tells administrators when a pass closed findings.
func (s *Service) EnableNotifications(admins AdminDirectory, inApp InAppNotifier) {
	s.admins, s.inApp = admins, inApp
}

func (s *Service) policy(ctx context.Context, tenantID shared.ID) tenantdom.AssetLivenessSettings {
	if s.settings == nil {
		return tenantdom.AssetLivenessSettings{}
	}
	al, err := s.settings.GetAssetLifecycleSettings(ctx, tenantID.String())
	if err != nil || al == nil {
		// Unreadable settings: the defaults, which never close a finding.
		s.logger.Warn("liveness: settings not read, using the defaults", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return tenantdom.AssetLivenessSettings{}
	}
	return al.LivenessSettings()
}

// Record stores observations of the organization's assets (from the
// coverage settlement). Nil-safe; a failure is logged, never returned: the
// coverage ledger is the source of truth for scanning, liveness a reading
// of it.
func (s *Service) Record(ctx context.Context, tenantID shared.ID, obs []liveness.AssetObservation) {
	if s == nil || len(obs) == 0 {
		return
	}
	th := s.policy(ctx, tenantID).Thresholds()
	moved, err := s.repo.Observe(ctx, tenantID, obs, th, s.now())
	if err != nil {
		s.logger.Warn("liveness: observations not recorded", "tenant_id", tenantID.String(), "count", len(obs), "error", logger.SanitizeError(err))
		return
	}
	if len(moved) > 0 {
		s.logger.Info("liveness states changed", "tenant_id", tenantID.String(), "assets", len(moved))
	}
}

// Result is what one pass did (or would do, for a dry run).
type Result struct {
	// Transitions counts state changes by the new state.
	Transitions map[liveness.State]int `json:"transitions"`
	// GoneHeld counts assets with open findings that met gone but waited:
	// the daily bound was reached.
	GoneHeld int         `json:"gone_held"`
	Closed   []shared.ID `json:"-"`
	// ClosedCritical counts the closed findings of the critical tier.
	ClosedCritical int         `json:"closed_critical"`
	Reopened       []shared.ID `json:"-"`
}

// decide re-decides the organization's rows with their guards, names
// before services (a service's host name decides first). apply writes each
// change; a dry run passes nil and only counts. It returns the gone assets
// after the pass.
func (s *Service) decide(ctx context.Context, tenantID shared.ID, pol tenantdom.AssetLivenessSettings,
	apply func(row liveness.Row, after liveness.Evidence) (bool, error), res *Result, final map[shared.ID]liveness.State) error {
	th := pol.Thresholds()
	now := s.now()
	goneToday, err := s.repo.GoneSince(ctx, tenantID, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	budget := pol.EffectiveMaxGonePerDay() - goneToday
	for _, services := range []bool{false, true} {
		if services && apply != nil {
			// A service nothing checked follows its host name.
			if _, err := s.repo.AddServicesOfGoneHosts(ctx, tenantID); err != nil {
				return err
			}
		}
		rows, err := s.repo.Rows(ctx, tenantID, services, Batch)
		if err != nil {
			return err
		}
		for _, row := range rows {
			g := row.Guards
			if apply == nil && services && !g.HostGone {
				// A dry run did not write the host names' new states: read
				// them from this pass.
				if st, ok := final[row.HostID]; ok && !row.HostID.IsZero() && st == liveness.StateGone {
					g.HostGone = true
				}
			}
			after, _ := row.Evidence.Settle(g, th, now)
			if after.State == liveness.StateGone && row.Evidence.State != liveness.StateGone && row.OpenFindings > 0 {
				if budget <= 0 {
					res.GoneHeld++
					g.Pinned = true // decide everything but gone
					after, _ = row.Evidence.Settle(g, th, now)
				} else {
					budget--
				}
			}
			final[row.AssetID] = after.State
			if after.State == row.Evidence.State && after.Reason == row.Evidence.Reason && row.Evidence.Since != nil {
				continue
			}
			moved := true
			if apply != nil {
				if moved, err = apply(row, after); err != nil {
					return err
				}
			}
			if moved && after.State != row.Evidence.State {
				res.Transitions[after.State]++
			}
		}
	}
	return nil
}

// ReconcileTenant runs one pass for one organization: re-decide the states,
// then close the findings of gone assets (when the organization turned it
// on) and reopen the findings of assets that are no longer gone.
func (s *Service) ReconcileTenant(ctx context.Context, tenantID shared.ID) (Result, error) {
	res := Result{Transitions: map[liveness.State]int{}}
	if tenantID.IsZero() {
		return res, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	pol := s.policy(ctx, tenantID)
	apply := func(row liveness.Row, after liveness.Evidence) (bool, error) {
		return s.repo.SetState(ctx, tenantID, row.AssetID, row.Evidence, after)
	}
	if err := s.decide(ctx, tenantID, pol, apply, &res, map[shared.ID]liveness.State{}); err != nil {
		return res, err
	}
	if pol.CloseFindingsWhenGone {
		closed, err := s.repo.CloseGone(ctx, tenantID, Batch)
		if err != nil {
			s.finish(ctx, tenantID, res)
			return res, err
		}
		res.Closed, res.ClosedCritical = closed.IDs, closed.Critical
	}
	reopened, err := s.repo.ReopenNotGone(ctx, tenantID, Batch)
	if err != nil {
		s.finish(ctx, tenantID, res)
		return res, err
	}
	res.Reopened = reopened
	s.finish(ctx, tenantID, res)
	return res, nil
}

// ReconcileAll runs a pass for every organization with something to
// decide; one organization's failure does not stop the others.
func (s *Service) ReconcileAll(ctx context.Context) (int, error) {
	tenants, err := s.repo.TenantsWithLiveness(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		res, err := s.ReconcileTenant(ctx, t)
		n += len(res.Closed) + len(res.Reopened)
		for _, c := range res.Transitions {
			n += c
		}
		if err != nil {
			s.logger.Warn("liveness pass failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return n, nil
}

// DryRun is what a pass would do now, written nowhere.
type DryRun struct {
	liveness.Preview
	Transitions map[liveness.State]int `json:"transitions"`
	GoneHeld    int                    `json:"gone_held"`
}

// Preview runs the pass without writing: the states after it, the findings
// that would close (if closing were on) and reopen, and the open findings
// that keep the "cannot verify" label.
func (s *Service) Preview(ctx context.Context, tenantID shared.ID) (DryRun, error) {
	out := DryRun{Transitions: map[liveness.State]int{}}
	pol := s.policy(ctx, tenantID)
	states, err := s.repo.StateCounts(ctx, tenantID)
	if err != nil {
		return out, err
	}
	res := Result{Transitions: out.Transitions}
	final := map[shared.ID]liveness.State{}
	stored := map[shared.ID]liveness.State{}
	// Read the stored states first so the histogram can move each row.
	for _, services := range []bool{false, true} {
		rows, err := s.repo.Rows(ctx, tenantID, services, Batch)
		if err != nil {
			return out, err
		}
		for _, r := range rows {
			stored[r.AssetID] = r.Evidence.State
		}
	}
	if err := s.decide(ctx, tenantID, pol, nil, &res, final); err != nil {
		return out, err
	}
	var gone, unreachable, unresolvable []shared.ID
	for id, st := range final {
		states[string(stored[id])]--
		states[string(st)]++
		switch st {
		case liveness.StateGone:
			gone = append(gone, id)
		case liveness.StateUnreachable:
			unreachable = append(unreachable, id)
		case liveness.StateUnresolvable:
			unresolvable = append(unresolvable, id)
		}
	}
	for k, v := range states {
		if v <= 0 {
			delete(states, k)
		}
	}
	out.States, out.GoneHeld, out.CloseFindingsWhenGone = states, res.GoneHeld, pol.CloseFindingsWhenGone
	if out.WouldCloseFindings, out.WouldCloseCritical, err = s.repo.CountOpenFindings(ctx, tenantID, gone); err != nil {
		return out, err
	}
	if out.OpenOnUnreachable, _, err = s.repo.CountOpenFindings(ctx, tenantID, unreachable); err != nil {
		return out, err
	}
	if out.OpenOnUnresolvable, _, err = s.repo.CountOpenFindings(ctx, tenantID, unresolvable); err != nil {
		return out, err
	}
	if out.WouldReopenFindings, err = s.repo.CountReopenable(ctx, tenantID, gone); err != nil {
		return out, err
	}
	return out, nil
}

// finish writes the pass's summary audit row and tells administrators of
// closed findings.
func (s *Service) finish(ctx context.Context, tenantID shared.ID, res Result) {
	moved := 0
	for _, n := range res.Transitions {
		moved += n
	}
	if moved == 0 && res.GoneHeld == 0 && len(res.Closed) == 0 && len(res.Reopened) == 0 {
		return
	}
	if s.audit != nil {
		actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: "system", ActorEmail: "asset-liveness@system"}
		ev := auditapp.NewSuccessEvent(auditdom.ActionAssetLivenessApplied, auditdom.ResourceTypeTenant, tenantID.String()).
			WithMessage(fmt.Sprintf("Asset liveness: %d state change(s), %d finding(s) closed as obsolete asset, %d reopened",
				moved, len(res.Closed), len(res.Reopened))).
			WithMetadata("transitions", res.Transitions).
			WithMetadata("gone_held", res.GoneHeld).
			WithMetadata("closed", len(res.Closed)).
			WithMetadata("closed_critical", res.ClosedCritical).
			WithMetadata("reopened", len(res.Reopened)).
			WithMetadata("closed_ids", sample(res.Closed, 50)).
			WithMetadata("reopened_ids", sample(res.Reopened, 50))
		if len(res.Closed) > 0 {
			ev = ev.WithSeverity(auditdom.SeverityHigh)
		}
		auditapp.RecordOrWarn(ctx, s.logger, s.audit, actx, ev)
	}
	if len(res.Closed) > 0 || res.GoneHeld > 0 {
		s.notify(ctx, tenantID, res)
	}
}

func (s *Service) notify(ctx context.Context, tenantID shared.ID, res Result) {
	if s.admins == nil || s.inApp == nil {
		return
	}
	title := fmt.Sprintf("%d finding(s) closed: their assets are gone", len(res.Closed))
	body := fmt.Sprintf("%d open finding(s) (%d critical, P0 or KEV) were closed as obsolete asset, not as fixed: "+
		"their names have had no address long enough. They reopen by themselves if an asset is seen again.",
		len(res.Closed), res.ClosedCritical)
	if res.GoneHeld > 0 {
		if len(res.Closed) == 0 {
			title = fmt.Sprintf("%d asset(s) wait to be marked gone", res.GoneHeld)
			body = ""
		}
		body += fmt.Sprintf(" %d more asset(s) met the gone rule but wait for tomorrow: the daily limit was reached. "+
			"Check the sensors' DNS if this is unexpected.", res.GoneHeld)
	}
	ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.logger.Warn("liveness: list admins", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, id := range ids {
		uid := id
		if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeSystemAlert, Severity: notificationdom.SeverityHigh,
			Title: title, Body: body, ResourceType: "asset", URL: "/findings?closure_reason=obsolete_asset",
		}); err != nil {
			s.logger.Warn("liveness: notify admin", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}

func sample(ids []shared.ID, n int) []string {
	out := make([]string, 0, min(len(ids), n))
	for i, id := range ids {
		if i == n {
			break
		}
		out = append(out, id.String())
	}
	return out
}
