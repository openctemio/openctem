// Package pagemon runs web page monitoring: watch management, the dispatch
// of due fetches through the coverage path, server-side change detection
// on fetch results, and alerts.
// Design: docs/rfcs/RFC-137-web-page-monitoring.md.
package pagemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Source is the exposure source of page monitoring.
const Source = "page_monitoring"

// goneNote marks exposures the monitor resolved itself.
const goneNote = "The page no longer loads scripts from this host."

// Store persists watches, snapshots and changes (*postgres.PageMonitorRepository).
// Every method is scoped to one tenant; list reads also take the caller's
// data scope (nil = internal caller, no narrowing).
type Store interface {
	ListWatches(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) ([]pagemon.Watch, error)
	GetWatch(ctx context.Context, tenantID, id shared.ID) (*pagemon.Watch, error)
	CountWatches(ctx context.Context, tenantID shared.ID) (int, error)
	CreateWatch(ctx context.Context, w *pagemon.Watch) error
	UpdateWatch(ctx context.Context, w *pagemon.Watch) error
	DeleteWatch(ctx context.Context, tenantID, id shared.ID) error
	ListChildren(ctx context.Context, tenantID, parentID shared.ID) ([]pagemon.Watch, error)
	OriginAsset(ctx context.Context, tenantID shared.ID, originName string) (shared.ID, error)
	EnabledWatchesByURL(ctx context.Context, tenantID shared.ID, urls []string) (map[string]pagemon.Watch, error)
	LatestSnapshot(ctx context.Context, tenantID, watchID shared.ID) (*pagemon.Snapshot, error)
	SaveFetch(ctx context.Context, tenantID shared.ID, o pagemon.FetchOutcome) error
	KnownHosts(ctx context.Context, tenantID shared.ID, hosts []string) (map[string]bool, error)
	TenantsWithDueWatches(ctx context.Context, now time.Time) ([]shared.ID, error)
	DueWatches(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]pagemon.Watch, error)
	MarkDispatched(ctx context.Context, tenantID shared.ID, ids []shared.ID, runID *shared.ID, now time.Time) error
	MarkHeld(ctx context.Context, tenantID shared.ID, reasons map[shared.ID]string, state pagemon.State, retryAt time.Time) error
	ListChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, f pagemon.ChangeFilter) ([]pagemon.Change, int, error)
	GetChange(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID) (*pagemon.Change, error)
	SuggestionCandidates(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]SuggestionCandidate, error)
	DeleteChangesBefore(ctx context.Context, before time.Time) (int64, error)
}

// SuggestionCandidate is an endpoint or origin the store found unwatched.
type SuggestionCandidate struct {
	AssetID    shared.ID
	AssetName  string
	Path       string
	Kind       string
	Labels     []string
	CatalogKey string
}

// Scope is the caller's data scope (*datascope.Enforcer).
type Scope interface {
	Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
	AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error
	AssertAssetRef(ctx context.Context, tenantID, assetID shared.ID) error
}

// Dispatcher starts a capability on targets through the coverage path
// (*scan.Service): scope gate, active-scan gate, zone routing, signed jobs.
type Dispatcher interface {
	StartCoverage(ctx context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error)
}

// TenantSwitch says whether automatic coverage runs for a tenant.
type TenantSwitch interface {
	CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
}

// Exposures writes exposures and announces new ones (*postgres.EASMExposureWriter).
type Exposures interface {
	BulkUpsert(ctx context.Context, events []*exposuredom.ExposureEvent) error
}

// Resolver resolves and reopens exposures the monitor manages (*postgres.EASMDNSRepository).
type Resolver interface {
	ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
	ReopenAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
}

// CapabilityKnown reports whether the platform can dispatch the fetch
// capability (its stage is in the catalog).
type CapabilityKnown func() bool

// Dispatch bounds.
const (
	dispatchPerTenant = 100
	dispatchPerHost   = 10
	suggestionLimit   = 100
)

// Service is page monitoring.
type Service struct {
	store     Store
	scope     Scope
	dispatch  Dispatcher
	coverage  TenantSwitch
	exposures Exposures
	resolver  Resolver
	known     CapabilityKnown
	log       *logger.Logger
	now       func() time.Time
}

// NewService creates the service. dispatch, coverage, exposures and
// resolver may be nil (that part is skipped).
func NewService(store Store, scope Scope, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: store, scope: scope, log: log, now: func() time.Time { return time.Now().UTC() },
		known: func() bool { return false }}
}

// SetDispatch wires the fetch dispatch.
func (s *Service) SetDispatch(d Dispatcher, sw TenantSwitch, known CapabilityKnown) {
	s.dispatch, s.coverage = d, sw
	if known != nil {
		s.known = known
	}
}

// SetAlerts wires exposures.
func (s *Service) SetAlerts(e Exposures, r Resolver) { s.exposures, s.resolver = e, r }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// WatchInput creates a watch.
type WatchInput struct {
	URL            string
	Mode           string
	CadenceHours   int
	IgnorePatterns []string
	Source         string
}

// WatchUpdate changes a watch.
type WatchUpdate struct {
	Enabled        *bool
	Mode           string
	CadenceHours   int
	IgnorePatterns []string
}

// ErrNoOrigin refuses a URL whose origin is not a known web service of the
// organization the caller can see (one answer for both, no oracle).
var ErrNoOrigin = fmt.Errorf("%w: the URL's origin is not a web service in your inventory", shared.ErrValidation)

// ErrLimit refuses a watch past the organization's maximum.
var ErrLimit = fmt.Errorf("%w: the organization watches the maximum number of URLs", shared.ErrConflict)

// ErrDerived refuses a change to a watch the platform manages.
var ErrDerived = fmt.Errorf("%w: this script is watched through its page; change the page's watch", shared.ErrValidation)

func parseMode(m string) (pagemon.Mode, error) {
	if m == "" {
		return pagemon.ModeJS, nil
	}
	mode := pagemon.Mode(m)
	if !mode.Valid() {
		return "", fmt.Errorf("%w: mode must be js or full", shared.ErrValidation)
	}
	return mode, nil
}

// ListWatches returns the watches whose asset is in the caller's data scope.
func (s *Service) ListWatches(ctx context.Context, tenantID shared.ID) ([]pagemon.Watch, error) {
	scope, err := s.scope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.ListWatches(ctx, tenantID, scope)
}

// CreateWatch adds a watch on a URL of one of the organization's web
// services the caller can see.
func (s *Service) CreateWatch(ctx context.Context, tenantID shared.ID, actor *shared.ID, in WatchInput) (*pagemon.Watch, error) {
	u, err := pagemon.NormalizeURL(in.URL)
	if err != nil {
		return nil, err
	}
	mode, err := parseMode(in.Mode)
	if err != nil {
		return nil, err
	}
	cadence, err := pagemon.NormalizeCadence(in.CadenceHours)
	if err != nil {
		return nil, err
	}
	patterns, err := pagemon.NormalizeIgnorePatterns(in.IgnorePatterns)
	if err != nil {
		return nil, err
	}
	src := pagemon.Source(in.Source)
	if in.Source == "" {
		src = pagemon.SourceManual
	}
	if !src.Valid() {
		return nil, fmt.Errorf("%w: source must be manual or suggested", shared.ErrValidation)
	}
	assetID, err := s.store.OriginAsset(ctx, tenantID, pagemon.OriginName(u))
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrNoOrigin
		}
		return nil, err
	}
	if err := s.scope.AssertAssetRef(ctx, tenantID, assetID); err != nil {
		return nil, ErrNoOrigin
	}
	n, err := s.store.CountWatches(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if n >= pagemon.MaxWatchesPerTenant {
		return nil, ErrLimit
	}
	now := s.now()
	w := &pagemon.Watch{
		ID: shared.NewID(), TenantID: tenantID, AssetID: assetID, URL: u, Mode: mode, Source: src, Enabled: true,
		CadenceHours: cadence, IgnorePatterns: patterns, State: pagemon.StatePending, NextDueAt: now,
		CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateWatch(ctx, w); err != nil {
		return nil, err
	}
	return w, nil
}

// watchInScope loads a watch the caller may see (shared.ErrNotFound otherwise).
func (s *Service) watchInScope(ctx context.Context, tenantID shared.ID, id string) (*pagemon.Watch, error) {
	wid, err := shared.IDFromString(id)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	w, err := s.store.GetWatch(ctx, tenantID, wid)
	if err != nil {
		return nil, err
	}
	if err := s.scope.AssertAsset(ctx, tenantID, w.AssetID); err != nil {
		return nil, shared.ErrNotFound
	}
	return w, nil
}

// UpdateWatch changes a watch. Any change clears the dynamic mark (the
// person has looked at it) and makes the watch due now.
func (s *Service) UpdateWatch(ctx context.Context, tenantID shared.ID, id string, in WatchUpdate) (*pagemon.Watch, error) {
	w, err := s.watchInScope(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if w.Source == pagemon.SourceDerived {
		return nil, ErrDerived
	}
	if in.Mode != "" {
		if w.Mode, err = parseMode(in.Mode); err != nil {
			return nil, err
		}
	}
	if in.CadenceHours != 0 {
		if w.CadenceHours, err = pagemon.NormalizeCadence(in.CadenceHours); err != nil {
			return nil, err
		}
	}
	if in.IgnorePatterns != nil {
		if w.IgnorePatterns, err = pagemon.NormalizeIgnorePatterns(in.IgnorePatterns); err != nil {
			return nil, err
		}
	}
	if in.Enabled != nil {
		w.Enabled = *in.Enabled
	}
	w.Dynamic, w.ChangeStreak = false, 0
	w.NextDueAt, w.UpdatedAt = s.now(), s.now()
	if err := s.store.UpdateWatch(ctx, w); err != nil {
		return nil, err
	}
	return w, nil
}

// DeleteWatch removes a watch, its derived scripts, snapshots and changes.
func (s *Service) DeleteWatch(ctx context.Context, tenantID shared.ID, id string) (*pagemon.Watch, error) {
	w, err := s.watchInScope(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if w.Source == pagemon.SourceDerived {
		return nil, ErrDerived
	}
	if err := s.store.DeleteWatch(ctx, tenantID, w.ID); err != nil {
		return nil, err
	}
	return w, nil
}

// ListChanges returns changes of watches the caller can see, newest first.
func (s *Service) ListChanges(ctx context.Context, tenantID shared.ID, f pagemon.ChangeFilter) ([]pagemon.Change, int, error) {
	scope, err := s.scope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.MinSeverity != "" && !f.MinSeverity.Valid() {
		return nil, 0, fmt.Errorf("%w: unknown severity", shared.ErrValidation)
	}
	return s.store.ListChanges(ctx, tenantID, scope, f)
}

// GetChange returns one change with its diff.
func (s *Service) GetChange(ctx context.Context, tenantID shared.ID, id string) (*pagemon.Change, error) {
	cid, err := shared.IDFromString(id)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	scope, err := s.scope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.GetChange(ctx, tenantID, scope, cid)
}

// Suggestions lists URLs worth watching that are not watched yet: each
// origin's root page, login and admin pages, and JS files.
func (s *Service) Suggestions(ctx context.Context, tenantID shared.ID) ([]pagemon.Suggestion, error) {
	scope, err := s.scope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	cands, err := s.store.SuggestionCandidates(ctx, tenantID, scope, suggestionLimit*3)
	if err != nil {
		return nil, err
	}
	out := make([]pagemon.Suggestion, 0, suggestionLimit)
	seen := map[string]bool{}
	for _, c := range cands {
		reason := suggestionReason(c)
		if reason == "" {
			continue
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		u, err := pagemon.NormalizeURL(strings.TrimRight(c.AssetName, "/") + path)
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, pagemon.Suggestion{URL: u, AssetID: c.AssetID, AssetName: c.AssetName, Reason: reason, Mode: pagemon.ModeJS})
		if len(out) == suggestionLimit {
			break
		}
	}
	return out, nil
}

func suggestionReason(c SuggestionCandidate) string {
	switch {
	case c.Kind == "root":
		return pagemon.ReasonRoot
	case strings.Contains(c.Path, "{"):
		return "" // a template: the real URL is not known
	case containsLabel(c.Labels, "auth:login"):
		return pagemon.ReasonLogin
	case adminEntry(c.CatalogKey):
		return pagemon.ReasonAdmin
	case c.Kind == "script":
		return pagemon.ReasonScript
	}
	return ""
}

// adminEntry reports whether a web endpoint catalog key is an admin or
// authentication surface.
func adminEntry(key string) bool {
	if key == "" {
		return false
	}
	e := webendpoint.DefaultCatalog.ByKey(key)
	return e != nil && (e.Category == "admin" || e.Category == "auth")
}

func containsLabel(ls []string, l string) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}

// Sweep deletes changes past their retention.
func (s *Service) Sweep(ctx context.Context) (int64, error) {
	return s.store.DeleteChangesBefore(ctx, s.now().Add(-pagemon.ChangeRetention))
}
