package automation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Versions and modes (RFC-125 §5).
//
// The nodes and edges of an automation are its draft: what the editor
// changes. Publishing stores the draft as an immutable Version. An
// automation in ModeLive runs its published version; one in ModeSimulate
// runs its draft and only records what it would do. Editing the draft never
// changes what a live automation runs until the next publish.

// Mode says whether an automation's runs act (live) or only record what they
// would do (simulate).
type Mode string

// Modes.
const (
	ModeSimulate Mode = "simulate"
	ModeLive     Mode = "live"
)

// IsValid reports whether m is a known mode.
func (m Mode) IsValid() bool { return m == ModeSimulate || m == ModeLive }

// VersionStatus is the state of a stored version.
type VersionStatus string

// Version statuses.
const (
	// VersionPublished: the version live runs execute (at most one per
	// automation).
	VersionPublished VersionStatus = "published"
	// VersionPendingApproval: published by one person, waiting for a second
	// person to approve it.
	VersionPendingApproval VersionStatus = "pending_approval"
	// VersionSuperseded: a later version was published.
	VersionSuperseded VersionStatus = "superseded"
	// VersionRetired: a pending version that was replaced or withdrawn
	// before anyone approved it.
	VersionRetired VersionStatus = "retired"
)

// ErrCodeNotPublished is the error code for a live automation without a
// published version.
const ErrCodeNotPublished = "WORKFLOW_NOT_PUBLISHED"

// DefinitionNode is one node of a stored definition. Its JSON shape is the
// node shape the API returns.
type DefinitionNode struct {
	ID          string     `json:"id"`
	NodeKey     string     `json:"node_key"`
	NodeType    NodeType   `json:"node_type"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	UIPosition  UIPosition `json:"ui_position"`
	Config      NodeConfig `json:"config"`
}

// DefinitionEdge is one edge of a stored definition.
type DefinitionEdge struct {
	SourceNodeKey string `json:"source_node_key"`
	TargetNodeKey string `json:"target_node_key"`
	SourceHandle  string `json:"source_handle,omitempty"`
	Label         string `json:"label,omitempty"`
}

// Definition is the graph of an automation as a version stores it.
type Definition struct {
	Nodes []DefinitionNode `json:"nodes"`
	Edges []DefinitionEdge `json:"edges"`
}

// DefinitionOf returns the definition of w's loaded graph, nodes ordered by
// key and edges by their ends, so the same graph always gives the same
// digest.
func DefinitionOf(w *Workflow) Definition {
	d := Definition{Nodes: make([]DefinitionNode, 0, len(w.Nodes)), Edges: make([]DefinitionEdge, 0, len(w.Edges))}
	for _, n := range w.Nodes {
		if n == nil {
			continue
		}
		d.Nodes = append(d.Nodes, DefinitionNode{
			ID: n.ID.String(), NodeKey: n.NodeKey, NodeType: n.NodeType, Name: n.Name,
			Description: n.Description, UIPosition: n.UIPosition, Config: n.Config,
		})
	}
	for _, e := range w.Edges {
		if e == nil {
			continue
		}
		d.Edges = append(d.Edges, DefinitionEdge{
			SourceNodeKey: e.SourceNodeKey, TargetNodeKey: e.TargetNodeKey, SourceHandle: e.SourceHandle, Label: e.Label,
		})
	}
	d.normalize()
	return d
}

func (d *Definition) normalize() {
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].NodeKey < d.Nodes[j].NodeKey })
	sort.Slice(d.Edges, func(i, j int) bool {
		a, b := d.Edges[i], d.Edges[j]
		if a.SourceNodeKey != b.SourceNodeKey {
			return a.SourceNodeKey < b.SourceNodeKey
		}
		if a.TargetNodeKey != b.TargetNodeKey {
			return a.TargetNodeKey < b.TargetNodeKey
		}
		return a.SourceHandle < b.SourceHandle
	})
}

// Digest is the SHA-256 (hex) of the definition's canonical JSON. Node ids
// and positions are left out: they do not change what the automation does.
func (d Definition) Digest() string {
	type node struct {
		NodeKey  string     `json:"k"`
		NodeType NodeType   `json:"t"`
		Name     string     `json:"n"`
		Config   NodeConfig `json:"c"`
	}
	canon := struct {
		Nodes []node           `json:"nodes"`
		Edges []DefinitionEdge `json:"edges"`
	}{Edges: d.Edges}
	for _, n := range d.Nodes {
		canon.Nodes = append(canon.Nodes, node{NodeKey: n.NodeKey, NodeType: n.NodeType, Name: n.Name, Config: n.Config})
	}
	// encoding/json writes map keys sorted, so the bytes are stable.
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Configs returns the node configs of the definition.
func (d Definition) Configs() []NodeConfig {
	out := make([]NodeConfig, 0, len(d.Nodes))
	for _, n := range d.Nodes {
		out = append(out, n.Config)
	}
	return out
}

// Materialize returns a copy of w whose graph is d (the graph a live run of
// a version executes). Node ids are the ones the version stored.
func (d Definition) Materialize(w *Workflow) *Workflow {
	cp := *w
	cp.Nodes = make([]*Node, 0, len(d.Nodes))
	cp.Edges = make([]*Edge, 0, len(d.Edges))
	for _, n := range d.Nodes {
		id, err := shared.IDFromString(n.ID)
		if err != nil {
			id = shared.NewID()
		}
		cp.Nodes = append(cp.Nodes, &Node{
			ID: id, WorkflowID: w.ID, NodeKey: n.NodeKey, NodeType: n.NodeType, Name: n.Name,
			Description: n.Description, UIPosition: n.UIPosition, Config: n.Config,
		})
	}
	for _, e := range d.Edges {
		cp.Edges = append(cp.Edges, &Edge{
			ID: shared.NewID(), WorkflowID: w.ID, SourceNodeKey: e.SourceNodeKey, TargetNodeKey: e.TargetNodeKey,
			SourceHandle: e.SourceHandle, Label: e.Label,
		})
	}
	return &cp
}

// Version is one immutable published definition of an automation.
type Version struct {
	ID           shared.ID
	TenantID     shared.ID
	AutomationID shared.ID
	Version      int
	Definition   Definition
	Digest       string
	RiskClass    RiskClass
	Status       VersionStatus
	PublishedBy  *shared.ID
	PublishedAt  *time.Time
	ApprovedBy   *shared.ID
	ApprovedAt   *time.Time
	StepUpAt     *time.Time
	CreatedAt    time.Time
}

// NewVersion builds the next version of w from its loaded graph (the number
// is assigned when it is stored).
func NewVersion(w *Workflow, by shared.ID, status VersionStatus) (*Version, error) {
	if w == nil || w.ID.IsZero() || w.TenantID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "automation is required", shared.ErrValidation)
	}
	def := DefinitionOf(w)
	if len(def.Nodes) == 0 {
		return nil, shared.NewDomainError("VALIDATION", "an automation without steps cannot be published", shared.ErrValidation)
	}
	v := &Version{
		ID: shared.NewID(), TenantID: w.TenantID, AutomationID: w.ID,
		Definition: def, Digest: def.Digest(), RiskClass: def.Risk(),
		Status: status, CreatedAt: time.Now(),
	}
	if !by.IsZero() {
		v.PublishedBy = &by
	}
	return v, nil
}

// VersionRepository stores versions. Every method is tenant-scoped.
type VersionRepository interface {
	// Create stores v with the next version number of its automation and
	// sets v.Version.
	Create(ctx context.Context, v *Version) error
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Version, error)
	// ListByAutomation lists the versions of an automation, newest first.
	ListByAutomation(ctx context.Context, tenantID, automationID shared.ID, limit int) ([]*Version, error)
	// Publish makes versionID the published version of its automation in
	// one transaction: the previous published version becomes superseded,
	// other pending versions are retired, and the automation switches to
	// live with published_version_id = versionID. approvedBy is the second
	// person who approved it (nil when none was needed).
	Publish(ctx context.Context, tenantID, automationID, versionID shared.ID, approvedBy *shared.ID, at time.Time) error
}

// ErrVersionNotPending is returned when a version is no longer waiting for
// approval (approved, retired or superseded meanwhile).
var ErrVersionNotPending = shared.NewDomainError("VERSION_CHANGED", "this version is no longer waiting for approval", shared.ErrConflict)

// String is for logs.
func (v *Version) String() string {
	return fmt.Sprintf("automation %s v%d (%s)", v.AutomationID, v.Version, v.Status)
}
