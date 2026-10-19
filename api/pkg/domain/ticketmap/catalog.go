package ticketmap

import "sort"

// AttrType is the shape of an attribute's value.
type AttrType string

const (
	TypeText   AttrType = "text"
	TypeNumber AttrType = "number"
	TypeDate   AttrType = "date"
	TypeBool   AttrType = "bool"
	TypeEnum   AttrType = "enum"
	TypeList   AttrType = "list"
	TypeUser   AttrType = "user"
	TypeLink   AttrType = "link"
	TypeTable  AttrType = "table" // a rendered block (findings table)
)

// InboundCap is what a tracker change of a mapped field may do to the
// attribute. It is a property of the attribute, fixed in code: a stored
// mapping can never widen it, and the apply path checks it again.
type InboundCap string

const (
	// InboundNever: the attribute is never changed from the tracker
	// (severity, scores, closing statuses, text).
	InboundNever InboundCap = "never"
	// InboundAssign: the tracker assignee becomes the OpenCTEM assignee when
	// it maps to a member who may be assigned.
	InboundAssign InboundCap = "assign"
	// InboundRequest: the change becomes a request a person decides (a due
	// date becomes an SLA-extension request, never a new deadline).
	InboundRequest InboundCap = "request"
	// InboundNote: the change is recorded on the timeline only (a tracker
	// priority never changes severity or priority).
	InboundNote InboundCap = "note"
)

// Attribute is one OpenCTEM value a mapping can use.
type Attribute struct {
	Path    string       `json:"path"`
	Kind    ObjectKind   `json:"kind"`
	Type    AttrType     `json:"type"`
	Tier    Minimization `json:"tier"`
	Inbound InboundCap   `json:"inbound"`
	// Enum lists the values of an enum attribute (value-map editors).
	Enum []string `json:"enum,omitempty"`
}

var severityEnum = []string{"critical", "high", "medium", "low", "info"}

var findingStatusEnum = []string{
	"new", "confirmed", "in_progress", "fix_applied", "resolved",
	"false_positive", "accepted", "duplicate",
}

// catalog is the complete list of mappable attributes. Paths are stable API.
//
//nolint:gochecknoglobals // static registry
var catalog = []Attribute{
	// Finding.
	{Path: "finding.title", Kind: ObjectFinding, Type: TypeText, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "finding.url", Kind: ObjectFinding, Type: TypeLink, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "finding.id", Kind: ObjectFinding, Type: TypeText, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "finding.severity", Kind: ObjectFinding, Type: TypeEnum, Tier: MinTitleOnly, Inbound: InboundNever, Enum: severityEnum},
	{Path: "finding.priority_class", Kind: ObjectFinding, Type: TypeEnum, Tier: MinTitleOnly, Inbound: InboundNote, Enum: []string{"P0", "P1", "P2", "P3"}},
	{Path: "finding.status", Kind: ObjectFinding, Type: TypeEnum, Tier: MinSummary, Inbound: InboundNever, Enum: findingStatusEnum},
	{Path: "finding.cvss_score", Kind: ObjectFinding, Type: TypeNumber, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.epss_score", Kind: ObjectFinding, Type: TypeNumber, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.is_kev", Kind: ObjectFinding, Type: TypeBool, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.cve_ids", Kind: ObjectFinding, Type: TypeList, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.cwe_ids", Kind: ObjectFinding, Type: TypeList, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.tags", Kind: ObjectFinding, Type: TypeList, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.source", Kind: ObjectFinding, Type: TypeEnum, Tier: MinSummary, Inbound: InboundNever,
		Enum: []string{"sast", "sca", "dast", "secret", "iac", "container", "cspm", "easm", "pentest", "bug_bounty", "red_team", "manual"}},
	{Path: "finding.tool", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.file_path", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.start_line", Kind: ObjectFinding, Type: TypeNumber, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.location", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.asset_name", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.asset_type", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.asset_criticality", Kind: ObjectFinding, Type: TypeEnum, Tier: MinSummary, Inbound: InboundNever,
		Enum: []string{"critical", "high", "medium", "low", "none"}},
	{Path: "finding.fix_guidance", Kind: ObjectFinding, Type: TypeText, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.sla_deadline", Kind: ObjectFinding, Type: TypeDate, Tier: MinSummary, Inbound: InboundRequest},
	{Path: "finding.sla_status", Kind: ObjectFinding, Type: TypeEnum, Tier: MinSummary, Inbound: InboundNever,
		Enum: []string{"on_track", "warning", "overdue", "exceeded", "not_applicable"}},
	{Path: "finding.first_seen_at", Kind: ObjectFinding, Type: TypeDate, Tier: MinSummary, Inbound: InboundNever},
	{Path: "finding.assignee", Kind: ObjectFinding, Type: TypeUser, Tier: MinSummary, Inbound: InboundAssign},
	{Path: "finding.description", Kind: ObjectFinding, Type: TypeText, Tier: MinFull, Inbound: InboundNever},

	// Remediation task.
	{Path: "task.title", Kind: ObjectTask, Type: TypeText, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "task.url", Kind: ObjectTask, Type: TypeLink, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "task.id", Kind: ObjectTask, Type: TypeText, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "task.priority", Kind: ObjectTask, Type: TypeEnum, Tier: MinTitleOnly, Inbound: InboundNote, Enum: []string{"critical", "high", "medium", "low"}},
	{Path: "task.status", Kind: ObjectTask, Type: TypeEnum, Tier: MinSummary, Inbound: InboundNever,
		Enum: []string{"open", "in_progress", "verifying", "done", "closed_unverified", "on_hold", "canceled", "archived"}},
	{Path: "task.finding_count", Kind: ObjectTask, Type: TypeNumber, Tier: MinTitleOnly, Inbound: InboundNever},
	{Path: "task.resolved_count", Kind: ObjectTask, Type: TypeNumber, Tier: MinSummary, Inbound: InboundNever},
	{Path: "task.progress", Kind: ObjectTask, Type: TypeNumber, Tier: MinSummary, Inbound: InboundNever},
	{Path: "task.due_date", Kind: ObjectTask, Type: TypeDate, Tier: MinSummary, Inbound: InboundRequest},
	{Path: "task.assignee", Kind: ObjectTask, Type: TypeUser, Tier: MinSummary, Inbound: InboundAssign},
	{Path: "task.findings_table", Kind: ObjectTask, Type: TypeTable, Tier: MinSummary, Inbound: InboundNever},
	{Path: "task.description", Kind: ObjectTask, Type: TypeText, Tier: MinFull, Inbound: InboundNever},
}

// Catalog returns the attributes of one object kind, sorted by path.
func Catalog(kind ObjectKind) []Attribute {
	out := make([]Attribute, 0, len(catalog))
	for _, a := range catalog {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// LookupAttr finds an attribute of an object kind.
func LookupAttr(kind ObjectKind, path string) (Attribute, bool) {
	for _, a := range catalog {
		if a.Kind == kind && a.Path == path {
			return a, true
		}
	}
	return Attribute{}, false
}
