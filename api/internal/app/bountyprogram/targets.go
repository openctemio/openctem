package bountyprogram

// Program targets go through the standard asset ingest (RFC-065 §16.8):
// every time a program's scope is applied (import, re-import, follow, feed
// reconcile, sync), its in-scope targets are ingested as the tenant's assets
// with the program's source, so they get the same dedup, attribute
// reconciliation and change timeline as any collector's assets, and the
// program records which assets are its targets. Program metadata (rules,
// terms, qualifiers) stays with the program.

import (
	"context"
	"fmt"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Program target sources (the asset source kind and name they ingest as).
const (
	TargetSourceFeed   = "programfeed"
	TargetSourceImport = "program-import"
	TargetSourceManual = "program-manual"
)

// TargetSource is how a program's targets are ingested: the source name
// (TargetSource*), whether it is a feed (else an import), the run (feed
// sequence or import id) and when the source saw the data.
type TargetSource struct {
	Name       string
	Feed       bool
	Run        string
	ObservedAt time.Time
}

// TargetIngester ingests a program's target assets for its tenant and
// records them as the program's targets (*programtarget.Ingester).
type TargetIngester interface {
	IngestProgramTargets(ctx context.Context, tenantID, programID shared.ID, src TargetSource, assets []bp.TargetAsset) error
}

// SetTargetIngester wires the target ingest.
func (s *Service) SetTargetIngester(i TargetIngester) { s.targets = i }

// targetSource is the source a program's targets ingest as.
func (s *Service) targetSource(ctx context.Context, p *bp.Program) TargetSource {
	switch p.ScopeSource {
	case bp.ScopeSourcePublicFeed:
		src := TargetSource{Name: TargetSourceFeed, Feed: true, ObservedAt: p.UpdatedAt}
		if p.PublicProgramID != nil && s.catalog != nil {
			if pub, err := s.catalog.GetPublic(ctx, *p.PublicProgramID); err == nil {
				src.Run = fmt.Sprintf("%s:%d", TargetSourceFeed, pub.Sequence)
				src.ObservedAt = firstTime(pub.Provenance.LastChanged, pub.Provenance.FetchedAt, pub.AsOf, p.UpdatedAt)
			}
		}
		return src
	case bp.ScopeSourceFileImport, bp.ScopeSourceFile, bp.ScopeSourceAPI:
		return TargetSource{Name: TargetSourceImport, Run: importRun(p), ObservedAt: p.UpdatedAt}
	}
	return TargetSource{Name: TargetSourceManual, Run: importRun(p), ObservedAt: p.UpdatedAt}
}

// importRun names one applied version of an imported scope: the program
// and its terms hash (the same scope is the same run).
func importRun(p *bp.Program) string {
	h := p.TermsSHA256
	if len(h) > 16 {
		h = h[:16]
	}
	return TargetSourceImport + ":" + p.ID.String() + ":" + h
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// ingestTargets ingests the program's targets. Best effort: the scope
// change is committed; the next application of the scope repeats it. An
// ended program keeps no targets.
func (s *Service) ingestTargets(ctx context.Context, p *bp.Program) {
	if s.targets == nil {
		return
	}
	var assets []bp.TargetAsset
	if p.Status != bp.StatusEnded {
		assets = bp.TargetAssets(p.ScopeItems)
	}
	if err := s.targets.IngestProgramTargets(ctx, p.TenantID, p.ID, s.targetSource(ctx, p), assets); err != nil {
		s.log.Warn("program target ingest failed; the next scope change retries", "program_id", p.ID.String(), "error", err)
	}
}
