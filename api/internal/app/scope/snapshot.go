package scope

// Scope snapshot per scan run (RFC-065 §9): which entries covered the run's
// targets when it started, the programs those entries belong to with their
// attestation and program exclusions, hashed. Identical scope gives the same
// hash and one stored body.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramLister lists the tenant's programs (*postgres.BountyProgramRepository).
type ProgramLister interface {
	List(ctx context.Context, tenantID shared.ID, memberOf *shared.ID) ([]*bountyprogram.Program, error)
}

// SnapshotStore keeps snapshots and links runs to them
// (*postgres.ScopeSnapshotRepository).
type SnapshotStore interface {
	Record(ctx context.Context, tenantID, runID shared.ID, sha256 string, body []byte, takenAt time.Time) error
}

// SetProgramLister wires the programs a snapshot names.
func (s *Service) SetProgramLister(p ProgramLister) { s.programs = p }

// noRoots: a snapshot records coverage, not proof.
type noRoots struct{}

func (noRoots) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) { return nil, nil }

// maxSnapshotTargets bounds one snapshot (a run dispatches at most 10 000).
const maxSnapshotTargets = 20000

// Snapshot builds the scope snapshot of a run's targets.
func (s *Service) Snapshot(ctx context.Context, tenantID shared.ID, targets []string) (*scopedom.Snapshot, error) {
	if len(targets) > maxSnapshotTargets {
		targets = targets[:maxSnapshotTargets]
	}
	auth, err := scopeauth.Load(ctx, tenantID, s, noRoots{})
	if err != nil {
		return nil, err
	}
	active, err := s.ListActiveTargets(ctx, tenantID.String())
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*scopedom.Target, len(active))
	for _, t := range active {
		byID[t.ID().String()] = t
	}
	snap := &scopedom.Snapshot{Targets: len(targets)}
	used := map[string]bool{}
	programIDs := map[shared.ID]bool{}
	for _, target := range targets {
		via, ok := auth.Covers(target)
		if !ok {
			snap.Uncovered++
			continue
		}
		if used[via.ID] {
			continue
		}
		used[via.ID] = true
		t := byID[via.ID]
		if t == nil {
			continue
		}
		e := scopedom.SnapshotEntry{ID: via.ID, TargetType: t.TargetType().String(), Pattern: t.Pattern(), Ports: t.Constraint().Ports, Protocol: t.Constraint().Protocol,
			Source: string(t.AuthorizationSource()), MaxTier: t.MaxTier().String(), ExpiresAt: t.ExpiresAt(), ApprovedAt: t.ApprovedAt()}
		if pid := t.ProgramID(); pid != nil {
			e.ProgramID = pid.String()
			programIDs[*pid] = true
		}
		snap.Entries = append(snap.Entries, e)
	}
	if len(programIDs) > 0 {
		if err := s.snapshotPrograms(ctx, tenantID, programIDs, snap); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

func (s *Service) snapshotPrograms(ctx context.Context, tenantID shared.ID, ids map[shared.ID]bool, snap *scopedom.Snapshot) error {
	if s.programs == nil || s.programExcl == nil {
		return fmt.Errorf("programs are not wired; the snapshot cannot name them")
	}
	list, err := s.programs.List(ctx, tenantID, nil)
	if err != nil {
		return fmt.Errorf("list programs: %w", err)
	}
	for _, p := range list {
		if !ids[p.ID] {
			continue
		}
		sp := scopedom.SnapshotProgram{ID: p.ID.String(), Name: p.Name, ProgramURL: p.ProgramURL,
			TermsSHA256: p.TermsSHA256, AcceptedAt: p.AcceptedAt}
		if p.AcceptedBy != nil {
			sp.AcceptedBy = p.AcceptedBy.String()
		}
		pid := p.ID
		ex, err := s.programExcl.Exclusions(ctx, tenantID, &pid)
		if err != nil {
			return fmt.Errorf("list program exclusions: %w", err)
		}
		for _, x := range ex {
			sp.Exclusions = append(sp.Exclusions, string(x.TargetType)+":"+x.Pattern)
		}
		snap.Programs = append(snap.Programs, sp)
	}
	return nil
}

// SnapshotRecorder records the scope snapshot of a scan run
// (scan.ScopeSnapshotRecorder).
type SnapshotRecorder struct {
	svc   *Service
	store SnapshotStore
}

// NewSnapshotRecorder wires the recorder.
func NewSnapshotRecorder(svc *Service, store SnapshotStore) *SnapshotRecorder {
	return &SnapshotRecorder{svc: svc, store: store}
}

// RecordRunSnapshot builds, hashes and stores the snapshot of one run.
func (r *SnapshotRecorder) RecordRunSnapshot(ctx context.Context, tenantID, runID shared.ID, targets []string) (string, error) {
	if r == nil || r.svc == nil || r.store == nil {
		return "", fmt.Errorf("scope snapshots are not wired")
	}
	snap, err := r.svc.Snapshot(ctx, tenantID, targets)
	if err != nil {
		return "", err
	}
	body, sum, err := snap.Canonical()
	if err != nil {
		return "", err
	}
	if err := r.store.Record(ctx, tenantID, runID, sum, body, time.Now().UTC()); err != nil {
		return "", err
	}
	return sum, nil
}
