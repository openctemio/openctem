// Package subscription stores the installation's signed license and answers,
// for every gate, which grant keys are on (design:
// docs/rfcs/RFC-145-enterprise-license-and-entitlements.md).
//
// The license is installation-wide state owned by platform administrators.
// Every stored file is re-verified with the roots compiled into the build
// (licensekey.Default) each time it is loaded, so a row written straight into
// the database grants nothing. With no license the installation is
// Community: every Community feature on, no grant key on. A license only
// adds grant keys; nothing here can deny or cap a Community feature, and
// sign-in, SSO, MFA and audit never depend on it.
//
// States are computed at the effective time (licensekey.EffectiveTime), and
// the stored time high-water mark only moves forward, so winding the clock
// back cannot revive an expired license. Any load error keeps the previous
// state; before the first successful load every grant is off (fail-closed:
// only granted extras depend on it).
package subscription

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/licensekey"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Source says how a license arrived.
type Source string

// Sources (the audit records them too).
const (
	SourceUpload Source = "upload"
	SourceCode   Source = "code"
	SourceSeed   Source = "seed"
	SourceRelay  Source = "relay"
)

// Tunables.
const (
	// pollInterval: how often Run checks for a license written by another
	// replica (one single-row read) and recomputes time-based states.
	pollInterval = 30 * time.Second
	// staleAfter: a snapshot older than this is reloaded on access (Run
	// is not running, or a reload kept failing).
	staleAfter = 2 * time.Minute
	// highWaterStep: the time high-water mark is persisted at most this often.
	highWaterStep = time.Hour
	// historyLimit bounds the licenses loaded (history beyond is kept in
	// the table but not evaluated).
	historyLimit = 200
)

// Errors of Activate and Remove.
var (
	// ErrExpired refuses storing a license that is already past its grace.
	ErrExpired = fmt.Errorf("%w: license has expired", shared.ErrValidation)
	// ErrAlreadyStored refuses storing a license id that is stored already.
	ErrAlreadyStored = fmt.Errorf("%w: license is stored already", shared.ErrConflict)
	// ErrNotFound: no stored (not removed) license with that id.
	ErrNotFound = fmt.Errorf("%w: license not found", shared.ErrNotFound)
)

// Record is one stored license (a row of subscription_licenses).
type Record struct {
	ID            shared.ID
	LicenseID     string
	CustomerID    string
	Type          licensekey.Type
	LicenseeName  string
	IssuedAt      time.Time
	NotBefore     time.Time
	ExpiresAt     time.Time
	GraceDays     int
	Entitlements  []limits.GrantKey
	KeySetVersion uint64
	SigningKeyID  string
	File          []byte
	Source        Source
	AddedBy       *shared.ID
	AddedAt       time.Time
	RemovedBy     *shared.ID
	RemovedAt     *time.Time
}

// State is the installation's license state row.
type State struct {
	InstallationID  string
	TimeHighWater   time.Time
	KeySetHighWater uint64
	Revoked         licensekey.Revocations
	Version         int64
}

// Repository stores licenses and the state row. Installation-wide: no
// method takes or returns organization data.
type Repository interface {
	State(ctx context.Context) (State, error)
	// Version returns the state row's version (bumped by Add and Remove).
	Version(ctx context.Context) (int64, error)
	// List returns up to limit licenses, newest first, removed ones included.
	List(ctx context.Context, limit int) ([]Record, error)
	// Add stores rec; in the same transaction it raises the key-set
	// high-water mark to keySetVersion, adds revoked to the stored
	// revocations, and bumps the version. A stored (not removed) license
	// with the same license id: ErrAlreadyStored.
	Add(ctx context.Context, rec Record, keySetVersion uint64, revoked licensekey.Revocations) error
	// Remove marks a stored license removed and bumps the version;
	// ErrNotFound when it is not stored or removed already.
	Remove(ctx context.Context, id shared.ID, by *shared.ID, at time.Time) error
	// AdvanceTimeHighWater raises the time high-water mark (never lowers it).
	AdvanceTimeHighWater(ctx context.Context, t time.Time) error
}

// Summary describes one license for display (platform administrators only;
// organizations see grant states, never the license).
type Summary struct {
	RecordID     shared.ID
	LicenseID    string
	CustomerID   string
	Type         licensekey.Type
	Licensee     string
	IssuerName   string
	IssuedAt     time.Time
	NotBefore    time.Time
	ExpiresAt    time.Time
	GraceEndsAt  time.Time
	GraceDays    int
	Entitlements []limits.GrantKey
	Meters       map[string]int64
	Bound        bool
	State        licensekey.State
	Source       Source
	AddedAt      time.Time
	RemovedAt    *time.Time
}

// StateCommunity is Status.State with no license in force or waiting.
const StateCommunity = "community"

// Status is the installation's license status (banners, console page).
type Status struct {
	// State: StateCommunity or the licensekey state of Current.
	State          string
	InstallationID string
	EffectiveTime  time.Time
	// ClockBehind: the wall clock is below the time high-water mark.
	ClockBehind bool
	// Current is the license in force, or else the newest stored one
	// (expired or not yet valid); nil in Community.
	Current *Summary
	// Pending are stored licenses that start later (renewals uploaded early).
	Pending []Summary
	// Grants holds the state of every registered grant key.
	Grants map[limits.GrantKey]limits.Grant
	// Invalid counts stored rows that no longer verify (ignored).
	Invalid int
}

type verified struct {
	rec Record
	lic *licensekey.License
}

type snapshot struct {
	state    State
	licenses []verified
	invalid  int
	version  int64
	loadedAt time.Time
	status   Status
}

// Service is the one entitlement answer for license grants.
type Service struct {
	repo     Repository
	verifier *licensekey.Verifier
	log      *logger.Logger
	now      func() time.Time

	mu   sync.Mutex
	snap *snapshot
}

// NewService builds the service. verifier is licensekey.Default() in
// production (tests/unit refuses anything else outside tests).
func NewService(repo Repository, verifier *licensekey.Verifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, verifier: verifier, log: log, now: time.Now}
}

// SetClock replaces the wall clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

var _ limits.GrantSource = (*Service)(nil)

// Status returns the current license status.
func (s *Service) Status(ctx context.Context) (Status, error) {
	snap, err := s.current(ctx)
	if err != nil {
		return Status{}, err
	}
	return snap.status, nil
}

// Has reports whether grant key is on for the installation. False when the
// state cannot be read (only granted extras depend on it).
func (s *Service) Has(ctx context.Context, key limits.GrantKey) bool {
	snap, err := s.current(ctx)
	if err != nil {
		return false
	}
	return snap.status.Grants[key].Status.Granting()
}

// Grants implements limits.GrantSource: the license grants the same to
// every organization; tenantID is never used to read anything.
func (s *Service) Grants(ctx context.Context, _ shared.ID) (map[limits.GrantKey]limits.Grant, error) {
	snap, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[limits.GrantKey]limits.Grant, len(snap.status.Grants))
	for k, g := range snap.status.Grants {
		out[k] = g
	}
	return out, nil
}

// Verify checks a license file against the stored state without storing it
// (the console preview).
func (s *Service) Verify(ctx context.Context, raw []byte) (*licensekey.License, error) {
	st, err := s.repo.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("read license state: %w", err)
	}
	return s.verifier.Verify(raw, licensekey.Options{
		MinKeySetVersion: st.KeySetHighWater, Revoked: st.Revoked, InstallationID: st.InstallationID,
	})
}

// Activate verifies a license file and stores it. A license already past
// its grace, or a license id already stored, is refused. Verification
// errors wrap the licensekey errors (licensekey.Reason gives the code).
func (s *Service) Activate(ctx context.Context, raw []byte, src Source, actor *shared.ID) (*Summary, error) {
	switch src {
	case SourceUpload, SourceCode, SourceSeed, SourceRelay:
	default:
		return nil, fmt.Errorf("%w: source %q", shared.ErrValidation, src)
	}
	lic, err := s.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	st, err := s.repo.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("read license state: %w", err)
	}
	eff := licensekey.EffectiveTime(s.now(), st.TimeHighWater, lic.IssuedAt)
	if lic.StateAt(eff) == licensekey.StateExpired {
		return nil, ErrExpired
	}
	rec := Record{
		ID: shared.NewID(), LicenseID: lic.ID, CustomerID: lic.CustomerID, Type: lic.Type, LicenseeName: lic.Licensee.Name,
		IssuedAt: lic.IssuedAt, NotBefore: lic.NotBefore, ExpiresAt: lic.ExpiresAt, GraceDays: graceDays(&lic.Claims),
		Entitlements: lic.Entitlements, KeySetVersion: lic.KeySet.Version, SigningKeyID: lic.KeyID,
		File: lic.File, Source: src, AddedBy: actor, AddedAt: s.now().UTC(),
	}
	if err := s.repo.Add(ctx, rec, lic.KeySet.Version, lic.KeySet.Revoked); err != nil {
		return nil, err
	}
	s.invalidate()
	sum := summarize(verified{rec: rec, lic: lic}, eff)
	return &sum, nil
}

// Remove removes a stored license at once (no grace: its grants become
// expired with the read-only period).
func (s *Service) Remove(ctx context.Context, recordID shared.ID, actor *shared.ID) error {
	if err := s.repo.Remove(ctx, recordID, actor, s.now().UTC()); err != nil {
		return err
	}
	s.invalidate()
	return nil
}

// Run keeps the snapshot fresh until ctx ends: it reloads when another
// replica wrote a license (the version changed), recomputes time-based
// states, and persists the time high-water mark at most hourly.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	s.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refresh(ctx)
		}
	}
}

func (s *Service) refresh(ctx context.Context) {
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	if snap != nil {
		v, err := s.repo.Version(ctx)
		if err != nil {
			s.log.Warn("license state: version check failed; keeping the previous state", "error", err)
			return
		}
		if v == snap.version {
			s.recompute(snap)
			s.persistHighWater(ctx)
			return
		}
	}
	if _, err := s.reload(ctx); err != nil {
		s.log.Warn("license state: reload failed; keeping the previous state", "error", err)
		return
	}
	s.persistHighWater(ctx)
}

// persistHighWater raises the stored time high-water mark to the
// effective time once it is highWaterStep ahead.
func (s *Service) persistHighWater(ctx context.Context) {
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	if snap == nil {
		return
	}
	eff := snap.status.EffectiveTime
	if eff.Sub(snap.state.TimeHighWater) < highWaterStep {
		return
	}
	if err := s.repo.AdvanceTimeHighWater(ctx, eff); err != nil {
		s.log.Warn("license state: could not store the time high-water mark", "error", err)
		return
	}
	s.mu.Lock()
	if s.snap == snap {
		s.snap.state.TimeHighWater = eff
	}
	s.mu.Unlock()
}

func (s *Service) invalidate() {
	s.mu.Lock()
	s.snap = nil
	s.mu.Unlock()
}

// current returns a fresh enough snapshot, loading it when there is none or
// it is stale. A failed reload keeps a previous snapshot.
func (s *Service) current(ctx context.Context) (*snapshot, error) {
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	if snap != nil && s.now().Sub(snap.loadedAt) < staleAfter {
		return snap, nil
	}
	fresh, err := s.reload(ctx)
	if err != nil {
		if snap != nil {
			s.log.Warn("license state: reload failed; keeping the previous state", "error", err)
			return snap, nil
		}
		return nil, err
	}
	return fresh, nil
}

func (s *Service) reload(ctx context.Context) (*snapshot, error) {
	st, err := s.repo.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("read license state: %w", err)
	}
	recs, err := s.repo.List(ctx, historyLimit)
	if err != nil {
		return nil, fmt.Errorf("list licenses: %w", err)
	}
	snap := &snapshot{state: st, version: st.Version}
	opts := licensekey.Options{Revoked: st.Revoked, InstallationID: st.InstallationID}
	for _, r := range recs {
		// Re-verified on every load: a row inserted or edited in the
		// database without a valid signature grants nothing. The key-set
		// rollback floor applies when a file is added, not here, so a stored
		// license keeps working after a renewal brings a newer key set;
		// revocations from the newest key set apply to every stored license.
		lic, err := s.verifier.Verify(r.File, opts)
		if err != nil {
			snap.invalid++
			s.log.Warn("stored license no longer verifies; ignored", "record_id", r.ID.String(), "reason", licensekey.Reason(err))
			continue
		}
		if lic.ID != r.LicenseID {
			snap.invalid++
			s.log.Warn("stored license row does not match its file; ignored", "record_id", r.ID.String())
			continue
		}
		snap.licenses = append(snap.licenses, verified{rec: r, lic: lic})
	}
	s.recompute(snap)
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
	return snap, nil
}

// recompute evaluates snap at the current effective time.
func (s *Service) recompute(snap *snapshot) {
	now := s.now()
	issued := make([]time.Time, 0, len(snap.licenses))
	for _, v := range snap.licenses {
		if v.rec.RemovedAt == nil {
			issued = append(issued, v.lic.IssuedAt)
		}
	}
	eff := licensekey.EffectiveTime(now, snap.state.TimeHighWater, issued...)
	st := evaluate(snap.licenses, eff)
	st.InstallationID = snap.state.InstallationID
	st.ClockBehind = now.Before(snap.state.TimeHighWater)
	st.Invalid = snap.invalid
	s.mu.Lock()
	snap.status = st
	snap.loadedAt = now
	s.mu.Unlock()
}

// evaluate is the pure license decision at effective time eff.
//
// The license in force is the stored (not removed) one in a granting state
// with the latest not_before; licenses are never merged. A key that an
// earlier license granted and the one in force does not (it expired, was
// removed or was superseded by a renewal without it) is expired, with its
// settings read-only for limits.GrantReadOnlyPeriod after that end.
func evaluate(all []verified, eff time.Time) Status {
	st := Status{State: StateCommunity, EffectiveTime: eff, Grants: map[limits.GrantKey]limits.Grant{}}
	var inForce, latest *verified
	for i := range all {
		v := &all[i]
		if v.rec.RemovedAt != nil {
			continue
		}
		state := v.lic.StateAt(eff)
		if state == licensekey.StateNotYetValid {
			st.Pending = append(st.Pending, summarize(*v, eff))
		}
		if state.Granting() && (inForce == nil || later(v, inForce)) {
			inForce = v
		}
		if state != licensekey.StateNotYetValid && (latest == nil || later(v, latest)) {
			latest = v
		}
	}
	sort.Slice(st.Pending, func(i, j int) bool { return st.Pending[i].NotBefore.Before(st.Pending[j].NotBefore) })
	current := inForce
	if current == nil {
		current = latest
	}
	switch {
	case current != nil:
		sum := summarize(*current, eff)
		st.Current, st.State = &sum, string(sum.State)
	case len(st.Pending) > 0:
		sum := st.Pending[0]
		st.Current, st.State = &sum, string(licensekey.StateNotYetValid)
	}

	for _, key := range limits.GrantKeys() {
		g := limits.Grant{Key: key, Status: limits.GrantNone}
		if inForce != nil && inForce.lic.Grants(key) {
			g.Status = grantStatus(inForce.lic.StateAt(eff))
			g.ExpiresAt, g.GraceEndsAt = inForce.lic.ExpiresAt, inForce.lic.GraceEndsAt()
			st.Grants[key] = g
			continue
		}
		// Ended grants: the latest end among licenses that granted the key.
		var end time.Time
		for i := range all {
			v := &all[i]
			if !v.lic.Grants(key) || v == inForce || !v.lic.NotBefore.Before(eff) {
				continue // never started, or the license in force
			}
			e := v.lic.GraceEndsAt()
			if v.rec.RemovedAt != nil && v.rec.RemovedAt.Before(e) {
				e = *v.rec.RemovedAt
			}
			if inForce != nil && inForce.lic.NotBefore.Before(e) {
				e = inForce.lic.NotBefore
			}
			if e.After(eff) {
				e = eff // defensive: an end is never after the effective time
			}
			if e.After(end) {
				end = e
				g.ExpiresAt, g.GraceEndsAt = v.lic.ExpiresAt, v.lic.GraceEndsAt()
			}
		}
		if !end.IsZero() {
			g.Status, g.ReadOnlyUntil = limits.GrantExpired, end.Add(limits.GrantReadOnlyPeriod)
		}
		st.Grants[key] = g
	}
	return st
}

// later orders licenses: later not_before, then later issued_at.
func later(a, b *verified) bool {
	if !a.lic.NotBefore.Equal(b.lic.NotBefore) {
		return a.lic.NotBefore.After(b.lic.NotBefore)
	}
	return a.lic.IssuedAt.After(b.lic.IssuedAt)
}

func grantStatus(s licensekey.State) limits.GrantStatus {
	switch s {
	case licensekey.StateActive:
		return limits.GrantActive
	case licensekey.StateExpiring:
		return limits.GrantExpiring
	case licensekey.StateGrace:
		return limits.GrantGrace
	case licensekey.StateExpired:
		return limits.GrantExpired
	case licensekey.StateNotYetValid:
		return limits.GrantNone
	}
	return limits.GrantNone
}

func graceDays(c *licensekey.Claims) int {
	if c.GraceDays == nil {
		return 0
	}
	return *c.GraceDays
}

func summarize(v verified, eff time.Time) Summary {
	c := &v.lic.Claims
	return Summary{
		RecordID: v.rec.ID, LicenseID: c.ID, CustomerID: c.CustomerID, Type: c.Type, Licensee: c.Licensee.Name,
		IssuerName: c.Issuer.Name, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore, ExpiresAt: c.ExpiresAt,
		GraceEndsAt: c.GraceEndsAt(), GraceDays: graceDays(c), Entitlements: c.Entitlements, Meters: c.Meters,
		Bound: c.Bind != nil && len(c.Bind.InstallationIDs) > 0, State: c.StateAt(eff),
		Source: v.rec.Source, AddedAt: v.rec.AddedAt, RemovedAt: v.rec.RemovedAt,
	}
}
