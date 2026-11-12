// Package exploration holds how OpenCTEM explains its own discovery work
// (docs/architecture/exploration.md, RFC-153).
//
// A story answers "how we found this" for one finding or asset: a short,
// ordered chain from the scope entry that covers it, through the assets it
// was discovered under, to the scans and sources that reported it. It is
// composed at read time from records the platform already keeps; nothing is
// copied.
package exploration

import (
	"context"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxSteps caps a story's chain whatever the stored records hold: the scope
// entry, at most six assets (the asset and five ancestors), up to two scan
// steps per report and MaxReports reports, and the finding.
const MaxSteps = 16

// MaxReports is how many reporting sources a finding story lists; the rest
// are counted (MoreReports), and the finding's "Seen by" list has them all.
const MaxReports = 3

// StepKind names what one step of a story is.
type StepKind string

const (
	// StepScopeEntry is the organization's scope entry that covers the
	// subject (or the closest ancestor it covers).
	StepScopeEntry StepKind = "scope_entry"
	// StepAsset is an asset of the discovery chain; the subject asset is
	// marked Subject.
	StepAsset StepKind = "asset"
	// StepScan is a scan run (and its step) that discovered, scanned or
	// reported the subject.
	StepScan StepKind = "scan"
	// StepReport is a source that reported the finding (a sighting) or the
	// upload that brought the asset in.
	StepReport StepKind = "report"
	// StepFinding is the finding itself, the end of a finding story.
	StepFinding StepKind = "finding"
)

// Scan roles: what a scan step did for the subject.
const (
	ScanDiscovered = "discovered" // the run derived the asset from a parent
	ScanScanned    = "scanned"    // the latest run that targeted the asset
	ScanReported   = "reported"   // the run of a source that reported the finding
)

// Step is one node of a story. Exactly one of the detail pointers matches
// Kind. A hidden step is one the caller may not see: it keeps its kind
// (and an asset its edge), nothing else.
type Step struct {
	Kind    StepKind
	Hidden  bool
	At      *time.Time
	Asset   *AssetStep
	Scope   *ScopeStep
	Scan    *ScanStep
	Report  *ReportStep
	Finding *FindingStep
}

// AssetStep is an asset of the discovery chain.
type AssetStep struct {
	ID   shared.ID
	Name string
	Type string
	// Via is how this asset leads to the next one down the chain (parent,
	// contains, exposes, serves_certificate, resolves_to); empty for the
	// subject.
	Via             string
	DiscoverySource string
	DiscoveryTool   string
	Subject         bool
}

// ScopeStep is the scope entry in effect that covers an asset of the chain.
type ScopeStep struct {
	ID         shared.ID
	TargetType string
	Pattern    string
	// AssetID is the asset of the chain the entry matches.
	AssetID shared.ID
	// ExcludedBy names an exclusion in effect that also matches the subject:
	// it is covered, but scanning it is refused.
	ExcludedBy string
}

// ScanStep is a scan run, with the step that acted when known.
type ScanStep struct {
	Role       string
	RunID      shared.ID
	ScanID     *shared.ID
	ScanName   string
	RunStatus  string
	StepRunID  *shared.ID
	StepName   string
	Capability string
	Tool       string
	// Relation is how a discovered asset was derived from its parent in the
	// run (resolves_to, contains, ...).
	Relation string
	// At is when the run started (else when it was created), or for an
	// asset's run, when the run recorded the asset.
	At *time.Time
}

// ReportStep is one source that reported the subject.
type ReportStep struct {
	Channel     string
	Tool        string
	ToolVersion string
	SensorID    *shared.ID
	SensorName  string
	Sender      string
	ReceiptID   *shared.ID
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	SeenCount   int
	Backfilled  bool
	// RunID and StepRunID name the run of this source's last report; the
	// story reads them into a scan step.
	RunID     *shared.ID
	StepRunID *shared.ID
}

// FindingStep is the finding at the end of a finding story.
type FindingStep struct {
	ID    shared.ID
	Title string
}

// Subject names what the story is about.
type Subject struct {
	Kind string // finding or asset
	ID   shared.ID
}

// Story is "how we found this" for one finding or asset, scope first and
// the subject last.
type Story struct {
	Subject     Subject
	Steps       []Step
	Hidden      int
	Truncated   bool
	MoreReports int
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
}

// Seal makes the story safe to return: every hidden step is stripped to its
// kind (an asset keeps its edge) so a reader that filled one in by mistake
// cannot leak it, hidden steps are counted, and a chain longer than MaxSteps
// keeps its subject end and is marked truncated.
func (s *Story) Seal() {
	if len(s.Steps) > MaxSteps {
		s.Steps = s.Steps[len(s.Steps)-MaxSteps:]
		s.Truncated = true
	}
	s.Hidden = 0
	for i, st := range s.Steps {
		if !st.Hidden {
			continue
		}
		clean := Step{Kind: st.Kind, Hidden: true}
		if st.Kind == StepAsset && st.Asset != nil {
			clean.Asset = &AssetStep{Via: st.Asset.Via}
		}
		s.Steps[i] = clean
		s.Hidden++
	}
}

// PickReports orders the sources by who reported first and keeps
// MaxReports of them; more is how many were left out.
func PickReports(in []ReportStep) (out []ReportStep, more int) {
	out = append([]ReportStep(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].FirstSeenAt.Before(out[j].FirstSeenAt) })
	if len(out) > MaxReports {
		more = len(out) - MaxReports
		out = out[:MaxReports]
	}
	return out, more
}

// RunRef names a scan run, and optionally one of its steps, to read for a
// story.
type RunRef struct {
	RunID     shared.ID
	StepRunID *shared.ID
}

// ReceiptRef is the ingest receipt that brought an asset in.
type ReceiptRef struct {
	ID         shared.ID
	SourceKind string
	Tool       string
	At         time.Time
}

// StoryStore reads the records a story is composed from. Every read is
// bound to the tenant on every join and returns bounded rows.
type StoryStore interface {
	// ScanRuns returns the runs of the tenant with the named step (StepRunID
	// set only when that step belongs to the run); a run of another tenant
	// or a missing one is absent.
	ScanRuns(ctx context.Context, tenantID shared.ID, refs []RunRef) ([]ScanStep, error)
	// AssetRuns returns the first run that derived the asset from a parent
	// and the latest run that planned it as a target (either may be nil),
	// At being when the run recorded the asset.
	AssetRuns(ctx context.Context, tenantID, assetID shared.ID) (discovered, scanned *ScanStep, err error)
	// AssetReceipt returns the upload receipt that created the asset, nil
	// when none is recorded.
	AssetReceipt(ctx context.Context, tenantID, assetID shared.ID) (*ReceiptRef, error)
}
