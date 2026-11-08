// Package exploration composes "how we found this" for a finding or an asset
// (docs/architecture/exploration.md, RFC-153).
package exploration

import (
	"context"
	"errors"
	"fmt"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// storyTimeout bounds the reads of one story.
const storyTimeout = 5 * time.Second

// Story subjects.
const (
	SubjectFinding = "finding"
	SubjectAsset   = "asset"
)

// FindingReader reads a finding exactly as GET /findings/{id} does: the same
// tenant, data scope and pentest campaign checks, so the story is readable
// by whoever may read the finding and by no one else.
type FindingReader interface {
	GetFindingWithScope(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool) (*vulnerability.Finding, error)
}

// AssetReader reads an asset and its discovery lineage within the caller's
// data scope (an asset outside it is not found; an ancestor outside it is a
// hidden node).
type AssetReader interface {
	GetAssetInCallerScope(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error)
	GetLineage(ctx context.Context, tenantID, assetID string) (*assetdom.Lineage, error)
}

// ScopeMatcher answers which scope entry in effect covers a value, and
// which exclusion in effect matches it.
type ScopeMatcher interface {
	Covering(target string) *scopedom.Target
	Exclusion(target string) *scopedom.RuleRef
}

// ScopeMatchers loads the organization's scope entries and exclusions once
// per story.
type ScopeMatchers func(ctx context.Context, tenantID string) (ScopeMatcher, error)

// Access is what the caller may see beyond the subject: scans (scans:read),
// the organization's sensors (sensors:read) and scope entries
// (attack_surface:scope:read).
type Access struct {
	UserID  string
	IsAdmin bool
	Scans   bool
	Sensors bool
	Scope   bool
}

// StoryService composes stories. Every part is optional except the subject
// readers: an unset part leaves its steps out.
type StoryService struct {
	findings  FindingReader
	assets    AssetReader
	sightings ingestreceipt.SightingReader
	store     exploration.StoryStore
	scope     ScopeMatchers
}

// NewStoryService creates the service.
func NewStoryService(findings FindingReader, assets AssetReader, sightings ingestreceipt.SightingReader,
	store exploration.StoryStore, scope ScopeMatchers) *StoryService {
	return &StoryService{findings: findings, assets: assets, sightings: sightings, store: store, scope: scope}
}

// FindingStory is how a finding was found: the scope entry, the asset's
// discovery chain, the sources that reported it (each with its scan run)
// and the finding. Not readable as a finding: not found.
func (s *StoryService) FindingStory(ctx context.Context, tenantID, findingID string, acc Access) (*exploration.Story, error) {
	ctx, cancel := context.WithTimeout(ctx, storyTimeout)
	defer cancel()
	f, err := s.findings.GetFindingWithScope(ctx, tenantID, findingID, acc.UserID, acc.IsAdmin)
	if err != nil {
		return nil, err
	}
	first, last := f.FirstDetectedAt(), f.LastSeenAt()
	story := &exploration.Story{
		Subject:     exploration.Subject{Kind: SubjectFinding, ID: f.ID()},
		FirstSeenAt: nonZero(first), LastSeenAt: nonZero(last),
	}
	if !f.AssetID().IsZero() {
		// The finding may be readable while its asset is not (a finding
		// assigned to the caller on an asset outside their scope): the
		// asset is then one hidden step, its chain is not walked and its
		// scope is not evaluated.
		a, err := s.assets.GetAssetInCallerScope(ctx, tenantID, f.AssetID().String())
		switch {
		case errors.Is(err, shared.ErrNotFound):
			story.Steps = append(story.Steps, exploration.Step{Kind: exploration.StepAsset, Hidden: true})
		case err != nil:
			return nil, fmt.Errorf("read asset: %w", err)
		default:
			if err := s.addAssetChain(ctx, story, a, false, acc); err != nil {
				return nil, err
			}
		}
	}
	if err := s.addReports(ctx, story, f.TenantID(), f.ID(), acc); err != nil {
		return nil, err
	}
	story.Steps = append(story.Steps, exploration.Step{Kind: exploration.StepFinding, At: nonZero(first),
		Finding: &exploration.FindingStep{ID: f.ID(), Title: f.Title()}})
	story.Seal()
	return story, nil
}

// AssetStory is how an asset was found: the scope entry, its discovery
// chain with the run that derived it, the upload that created it and the
// latest run that scanned it. Outside the caller's data scope: not found.
func (s *StoryService) AssetStory(ctx context.Context, tenantID, assetID string, acc Access) (*exploration.Story, error) {
	ctx, cancel := context.WithTimeout(ctx, storyTimeout)
	defer cancel()
	a, err := s.assets.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	firstSeen, lastSeen := a.FirstSeen(), a.LastSeen()
	story := &exploration.Story{
		Subject:     exploration.Subject{Kind: SubjectAsset, ID: a.ID()},
		FirstSeenAt: nonZero(firstSeen), LastSeenAt: nonZero(lastSeen),
	}
	if err := s.addAssetChain(ctx, story, a, true, acc); err != nil {
		return nil, err
	}
	if s.store != nil {
		if err := s.addAssetSources(ctx, story, a.TenantID(), a.ID(), acc); err != nil {
			return nil, err
		}
	}
	story.Seal()
	return story, nil
}

// addAssetChain appends the scope entry and the discovery chain of an
// asset the caller may see, root first. subject is set for an asset story,
// where the run that derived the asset is placed right before it.
func (s *StoryService) addAssetChain(ctx context.Context, story *exploration.Story, a *assetdom.Asset,
	subject bool, acc Access) error {
	tenantID, assetID := a.TenantID(), a.ID()
	lin, err := s.assets.GetLineage(ctx, tenantID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("read asset lineage: %w", err)
	}
	story.Truncated = story.Truncated || lin.Truncated
	if acc.Scope && s.scope != nil {
		step, err := s.scopeStep(ctx, a, lin)
		if err != nil {
			return err
		}
		if step != nil {
			story.Steps = append(story.Steps, *step)
		}
	}
	for i := len(lin.Nodes) - 1; i >= 0; i-- {
		n := lin.Nodes[i]
		if n.Depth == 0 && subject && s.store != nil {
			if err := s.addDiscoveredRun(ctx, story, tenantID, assetID, acc); err != nil {
				return err
			}
		}
		story.Steps = append(story.Steps, assetStep(n, subject))
	}
	return nil
}

func assetStep(n assetdom.LineageNode, subject bool) exploration.Step {
	if n.Hidden {
		return exploration.Step{Kind: exploration.StepAsset, Hidden: true, Asset: &exploration.AssetStep{Via: n.Via}}
	}
	at := n.DiscoveredAt
	if at == nil {
		at = n.FirstSeen
	}
	return exploration.Step{Kind: exploration.StepAsset, At: at, Asset: &exploration.AssetStep{
		ID: n.ID, Name: n.Name, Type: string(n.Type), Via: n.Via,
		DiscoverySource: n.DiscoverySource, DiscoveryTool: n.DiscoveryTool, Subject: subject && n.Depth == 0,
	}}
}

// scopeStep names the scope entry in effect that covers the asset or, if
// none does, its closest visible ancestor. A hidden ancestor is never
// tested: an entry matching it would reveal its name.
func (s *StoryService) scopeStep(ctx context.Context, a *assetdom.Asset, lin *assetdom.Lineage) (*exploration.Step, error) {
	m, err := s.scope(ctx, a.TenantID().String())
	if err != nil {
		return nil, fmt.Errorf("load scope entries: %w", err)
	}
	if m == nil {
		return nil, nil //nolint:nilnil // no scope entries to match is no step
	}
	own := scopeapp.AssetMatchValues(a.Type().String(), a.Name(), a.Properties())
	excluded := ""
	for _, v := range own {
		if x := m.Exclusion(v); x != nil {
			excluded = x.Pattern
			break
		}
	}
	match := func(id shared.ID, values []string) *exploration.Step {
		for _, v := range values {
			if t := m.Covering(v); t != nil {
				return &exploration.Step{Kind: exploration.StepScopeEntry, Scope: &exploration.ScopeStep{
					ID: t.ID(), TargetType: t.TargetType().String(), Pattern: t.Pattern(), AssetID: id, ExcludedBy: excluded,
				}}
			}
		}
		return nil
	}
	if st := match(a.ID(), own); st != nil {
		return st, nil
	}
	for _, n := range lin.Nodes {
		if n.Depth == 0 || n.Hidden {
			continue
		}
		if st := match(n.ID, []string{n.Name}); st != nil {
			return st, nil
		}
	}
	return nil, nil //nolint:nilnil // no entry covers the chain
}

func (s *StoryService) addDiscoveredRun(ctx context.Context, story *exploration.Story, tenantID, assetID shared.ID, acc Access) error {
	d, _, err := s.store.AssetRuns(ctx, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("read asset runs: %w", err)
	}
	if d != nil {
		story.Steps = append(story.Steps, scanStep(*d, acc))
	}
	return nil
}

// addAssetSources appends the upload that created the asset and the latest
// run that scanned it.
func (s *StoryService) addAssetSources(ctx context.Context, story *exploration.Story, tenantID, assetID shared.ID, acc Access) error {
	r, err := s.store.AssetReceipt(ctx, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("read asset receipt: %w", err)
	}
	if r != nil {
		at := r.At
		id := r.ID
		story.Steps = append(story.Steps, exploration.Step{Kind: exploration.StepReport, At: &at, Report: &exploration.ReportStep{
			Channel: string(ingestreceipt.ChannelOf(ingestreceipt.SourceKind(r.SourceKind))), Tool: r.Tool,
			ReceiptID: &id, FirstSeenAt: at, LastSeenAt: at, SeenCount: 1,
		}})
	}
	_, scanned, err := s.store.AssetRuns(ctx, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("read asset runs: %w", err)
	}
	if scanned != nil {
		story.Steps = append(story.Steps, scanStep(*scanned, acc))
	}
	return nil
}

func scanStep(sc exploration.ScanStep, acc Access) exploration.Step {
	if !acc.Scans {
		return exploration.Step{Kind: exploration.StepScan, Hidden: true}
	}
	return exploration.Step{Kind: exploration.StepScan, At: sc.At, Scan: &sc}
}

// addReports appends the first MaxReports sources that reported the
// finding, first reporter first, each preceded by the run of its last
// report. The sensor is shown with sensors:read only; a run is a hidden step
// without scans:read.
func (s *StoryService) addReports(ctx context.Context, story *exploration.Story, tenantID, findingID shared.ID, acc Access) error {
	if s.sightings == nil {
		return nil
	}
	rows, err := s.sightings.FindingSightings(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("read finding sightings: %w", err)
	}
	all := make([]exploration.ReportStep, 0, len(rows))
	for _, r := range rows {
		rep := exploration.ReportStep{Channel: string(r.Channel), Tool: r.Tool, ToolVersion: r.ToolVersion, Sender: r.Sender,
			FirstSeenAt: r.FirstSeenAt, LastSeenAt: r.LastSeenAt, SeenCount: r.SeenCount, Backfilled: r.Backfilled,
			RunID: r.LastRunID, StepRunID: r.LastStepRunID}
		if acc.Sensors && r.SensorID != nil {
			rep.SensorID, rep.SensorName = r.SensorID, r.SensorName
		}
		if r.ReceiptKept {
			rep.ReceiptID = r.LastReceiptID
		}
		all = append(all, rep)
	}
	picked, more := exploration.PickReports(all)
	story.MoreReports = more
	runs, err := s.reportRuns(ctx, tenantID, picked, acc)
	if err != nil {
		return err
	}
	for _, rep := range picked {
		if rep.RunID != nil {
			if !acc.Scans {
				story.Steps = append(story.Steps, exploration.Step{Kind: exploration.StepScan, Hidden: true})
			} else if sc, ok := runs[*rep.RunID]; ok {
				sc.Role = exploration.ScanReported
				story.Steps = append(story.Steps, scanStep(sc, acc))
			}
		}
		at := rep.FirstSeenAt
		r := rep
		story.Steps = append(story.Steps, exploration.Step{Kind: exploration.StepReport, At: &at, Report: &r})
	}
	return nil
}

// reportRuns reads the runs of the picked reports in one query (none
// without scans:read).
func (s *StoryService) reportRuns(ctx context.Context, tenantID shared.ID, picked []exploration.ReportStep,
	acc Access) (map[shared.ID]exploration.ScanStep, error) {
	if !acc.Scans || s.store == nil {
		return nil, nil
	}
	refs := make([]exploration.RunRef, 0, len(picked))
	for _, r := range picked {
		if r.RunID != nil {
			refs = append(refs, exploration.RunRef{RunID: *r.RunID, StepRunID: r.StepRunID})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	rows, err := s.store.ScanRuns(ctx, tenantID, refs)
	if err != nil {
		return nil, fmt.Errorf("read report runs: %w", err)
	}
	out := make(map[shared.ID]exploration.ScanStep, len(rows))
	for _, r := range rows {
		out[r.RunID] = r
	}
	return out, nil
}

func nonZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
