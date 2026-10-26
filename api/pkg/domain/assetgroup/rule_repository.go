package assetgroup

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RuleState is the rule of a group and how its last evaluation went.
type RuleState struct {
	GroupID     shared.ID
	Rule        *Rule
	EditorID    *shared.ID
	Status      string
	EvaluatedAt *time.Time
	// Excluded counts the assets a person took out of the group.
	Excluded int
}

// RuleGroupRef names a group that has a rule.
type RuleGroupRef struct {
	GroupID  shared.ID
	TenantID shared.ID
	EditorID *shared.ID
}

// ApplyInput is the result of evaluating a rule, to be written as the
// group's rule members.
type ApplyInput struct {
	TenantID shared.ID
	GroupID  shared.ID
	// AssetIDs are the rule's matches (already limited to the editor's data
	// scope); the store drops the excluded ones and any that are not the
	// tenant's.
	AssetIDs []shared.ID
	// Cap is the most members the group may hold; the store refuses a
	// result over it and changes nothing.
	Cap int
}

// ApplyResult is what applying a rule changed.
type ApplyResult struct {
	Joined int
	Left   int
	// OverCap is set when the result would exceed Cap: nothing changed.
	OverCap bool
}

// Member is one member row as the group page lists it.
type Member struct {
	AssetID shared.ID
	Source  string
	AddedAt time.Time
}

// HistoryEntry is one join or leave of a group.
type HistoryEntry struct {
	ID        shared.ID  `json:"id"`
	GroupID   shared.ID  `json:"group_id"`
	GroupName string     `json:"group_name,omitempty"`
	AssetID   shared.ID  `json:"asset_id"`
	AssetName string     `json:"asset_name"`
	Action    string     `json:"action"` // joined | left
	Source    string     `json:"source"`
	Reason    string     `json:"reason"`
	ActorID   *shared.ID `json:"actor_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// History actions and reasons.
const (
	ActionJoined = "joined"
	ActionLeft   = "left"

	ReasonMatchesRule   = "matches_rule"
	ReasonNoLongerMatch = "no_longer_matches"
	ReasonAddedByHand   = "added_by_hand"
	ReasonAddedByPaste  = "added_by_paste"
	ReasonRemovedByHand = "removed_by_hand"
	ReasonRuleRemoved   = "rule_removed"
)

// Use names a team or a scan that depends on a group.
type Use struct {
	ID   shared.ID `json:"id"`
	Name string    `json:"name"`
	// Privileged is set for a team that holds a privileged role.
	Privileged bool `json:"privileged,omitempty"`
}

// RuleStore persists group rules, member sources, exclusions and history.
// Every method is tenant-scoped in SQL.
type RuleStore interface {
	// GetRuleState returns the group's rule state (Rule nil when the group
	// has none), or shared.ErrNotFound for a group of another tenant.
	GetRuleState(ctx context.Context, tenantID, groupID shared.ID) (*RuleState, error)
	// GetRuleSummaries returns the rule state of each listed group that has
	// a rule, keyed by group id (no exclusion count).
	GetRuleSummaries(ctx context.Context, tenantID shared.ID, groupIDs []shared.ID) (map[shared.ID]*RuleState, error)
	// SetRule stores (or with nil clears) the rule and its editor, and
	// resets the status. Clearing turns the rule members into manual ones.
	SetRule(ctx context.Context, tenantID, groupID shared.ID, rule *Rule, editorID *shared.ID, actorID *shared.ID) error
	// SetRuleStatus records the outcome of an evaluation.
	SetRuleStatus(ctx context.Context, tenantID, groupID shared.ID, status string) error
	// ListRuleGroups lists the groups that have a rule: of one tenant, or of
	// every tenant when tenantID is zero (the periodic recompute).
	ListRuleGroups(ctx context.Context, tenantID shared.ID) ([]RuleGroupRef, error)
	// ApplyRule writes a rule evaluation: the rule members become exactly
	// AssetIDs minus the exclusions, in one transaction, with history.
	ApplyRule(ctx context.Context, in ApplyInput) (ApplyResult, error)
	// RuleMemberIDs returns the ids of the group's members of one source.
	RuleMemberIDs(ctx context.Context, tenantID, groupID shared.ID, source string) ([]shared.ID, error)
	// AddMembers adds assets of the tenant with a source, clears their
	// exclusion, and records history. A rule member added by hand becomes a
	// manual one. It returns the assets that were not members before.
	AddMembers(ctx context.Context, tenantID, groupID shared.ID, assetIDs []shared.ID, source string, actorID *shared.ID) (int, error)
	// RemoveMembers removes members. With exclude, each asset also becomes
	// an exclusion, so a rule never brings it back.
	RemoveMembers(ctx context.Context, tenantID, groupID shared.ID, assetIDs []shared.ID, exclude bool, actorID *shared.ID) (int, error)
	// ExcludedIDs returns the assets taken out of the group by hand.
	ExcludedIDs(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error)
	// ListHistory pages the group's history, newest first.
	ListHistory(ctx context.Context, tenantID, groupID shared.ID, page pagination.Pagination) (pagination.Result[*HistoryEntry], error)
	// ListAssetHistory pages the groups an asset joined and left.
	ListAssetHistory(ctx context.Context, tenantID, assetID shared.ID, page pagination.Pagination) (pagination.Result[*HistoryEntry], error)
	// RelatedAssetIDs returns the services, URLs, certificates and
	// applications linked to the hosts (by parent or relationship), limited
	// to assets of the tenant.
	RelatedAssetIDs(ctx context.Context, tenantID shared.ID, hostIDs []shared.ID) ([]shared.ID, error)
	// EditorActive reports whether the user is still an active member of the
	// tenant (a rule evaluates as its editor, who may have left).
	EditorActive(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// ScanUses lists the scans that target the group.
	ScanUses(ctx context.Context, tenantID, groupID shared.ID) ([]Use, error)
	// TeamUses lists the teams whose scope rules name the group.
	TeamUses(ctx context.Context, tenantID, groupID shared.ID) ([]Use, error)
}
