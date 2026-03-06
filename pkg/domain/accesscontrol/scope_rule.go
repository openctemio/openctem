package accesscontrol

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ScopeRuleType represents the type of scope rule.
type ScopeRuleType string

const (
	// ScopeRuleTagMatch matches assets by their tags.
	ScopeRuleTagMatch ScopeRuleType = "tag_match"
	// ScopeRuleAssetGroupMatch matches assets by their asset group membership.
	ScopeRuleAssetGroupMatch ScopeRuleType = "asset_group_match"
)

// AllScopeRuleTypes returns all valid scope rule types.
func AllScopeRuleTypes() []ScopeRuleType {
	return []ScopeRuleType{ScopeRuleTagMatch, ScopeRuleAssetGroupMatch}
}

// IsValid checks if the scope rule type is valid.
func (t ScopeRuleType) IsValid() bool {
	return slices.Contains(AllScopeRuleTypes(), t)
}

// String returns the string representation.
func (t ScopeRuleType) String() string {
	return string(t)
}

// MatchLogic represents how multiple match criteria are combined.
type MatchLogic string

const (
	// MatchLogicAny means asset must match ANY of the criteria (OR).
	MatchLogicAny MatchLogic = "any"
	// MatchLogicAll means asset must match ALL criteria (AND).
	MatchLogicAll MatchLogic = "all"
)

// IsValid checks if the match logic is valid.
func (m MatchLogic) IsValid() bool {
	return m == MatchLogicAny || m == MatchLogicAll
}

// ScopeRule represents a dynamic asset-to-group scoping rule.
type ScopeRule struct {
	id                 shared.ID
	tenantID           shared.ID
	groupID            shared.ID
	name               string
	description        string
	ruleType           ScopeRuleType
	matchTags          []string
	matchLogic         MatchLogic
	matchAssetGroupIDs []shared.ID
	ownershipType      OwnershipType
	priority           int
	isActive           bool
	createdAt          time.Time
	updatedAt          time.Time
	createdBy          *shared.ID
}

// MaxScopeRulesPerGroup is the maximum number of scope rules per group.
const MaxScopeRulesPerGroup = 20

// MaxMatchTags is the maximum number of tags per tag_match rule.
const MaxMatchTags = 10

// MaxMatchAssetGroups is the maximum number of asset groups per asset_group_match rule.
const MaxMatchAssetGroups = 5

// NewScopeRule creates a new scope rule.
func NewScopeRule(
	tenantID, groupID shared.ID,
	name string,
	ruleType ScopeRuleType,
	createdBy *shared.ID,
) (*ScopeRule, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required", shared.ErrValidation)
	}
	if groupID.IsZero() {
		return nil, fmt.Errorf("%w: groupID is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if !ruleType.IsValid() {
		return nil, fmt.Errorf("%w: invalid rule type: %s", shared.ErrValidation, ruleType)
	}

	now := time.Now().UTC()
	return &ScopeRule{
		id:            shared.NewID(),
		tenantID:      tenantID,
		groupID:       groupID,
		name:          name,
		ruleType:      ruleType,
		matchLogic:    MatchLogicAny,
		ownershipType: OwnershipSecondary,
		isActive:      true,
		createdAt:     now,
		updatedAt:     now,
		createdBy:     createdBy,
	}, nil
}

// ReconstituteScopeRule recreates a ScopeRule from persistence.
func ReconstituteScopeRule(
	id, tenantID, groupID shared.ID,
	name, description string,
	ruleType ScopeRuleType,
	matchTags []string,
	matchLogic MatchLogic,
	matchAssetGroupIDs []shared.ID,
	ownershipType OwnershipType,
	priority int,
	isActive bool,
	createdAt, updatedAt time.Time,
	createdBy *shared.ID,
) *ScopeRule {
	return &ScopeRule{
		id:                 id,
		tenantID:           tenantID,
		groupID:            groupID,
		name:               name,
		description:        description,
		ruleType:           ruleType,
		matchTags:          matchTags,
		matchLogic:         matchLogic,
		matchAssetGroupIDs: matchAssetGroupIDs,
		ownershipType:      ownershipType,
		priority:           priority,
		isActive:           isActive,
		createdAt:          createdAt,
		updatedAt:          updatedAt,
		createdBy:          createdBy,
	}
}

// Getters

func (r *ScopeRule) ID() shared.ID                   { return r.id }
func (r *ScopeRule) TenantID() shared.ID             { return r.tenantID }
func (r *ScopeRule) GroupID() shared.ID              { return r.groupID }
func (r *ScopeRule) Name() string                    { return r.name }
func (r *ScopeRule) Description() string             { return r.description }
func (r *ScopeRule) RuleType() ScopeRuleType         { return r.ruleType }
func (r *ScopeRule) MatchTags() []string             { return r.matchTags }
func (r *ScopeRule) MatchLogic() MatchLogic          { return r.matchLogic }
func (r *ScopeRule) MatchAssetGroupIDs() []shared.ID { return r.matchAssetGroupIDs }
func (r *ScopeRule) OwnershipType() OwnershipType    { return r.ownershipType }
func (r *ScopeRule) Priority() int                   { return r.priority }
func (r *ScopeRule) IsActive() bool                  { return r.isActive }
func (r *ScopeRule) CreatedAt() time.Time            { return r.createdAt }
func (r *ScopeRule) UpdatedAt() time.Time            { return r.updatedAt }
func (r *ScopeRule) CreatedBy() *shared.ID           { return r.createdBy }

// Setters

func (r *ScopeRule) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	r.name = name
	r.updatedAt = time.Now().UTC()
	return nil
}

func (r *ScopeRule) UpdateDescription(description string) {
	r.description = description
	r.updatedAt = time.Now().UTC()
}

func (r *ScopeRule) SetMatchTags(tags []string, logic MatchLogic) error {
	if r.ruleType != ScopeRuleTagMatch {
		return fmt.Errorf("%w: match_tags only valid for tag_match rules", shared.ErrValidation)
	}
	if len(tags) == 0 {
		return fmt.Errorf("%w: at least one tag is required", shared.ErrValidation)
	}
	if len(tags) > MaxMatchTags {
		return fmt.Errorf("%w: maximum %d tags per rule", shared.ErrValidation, MaxMatchTags)
	}
	for _, tag := range tags {
		if len(strings.TrimSpace(tag)) == 0 {
			return fmt.Errorf("%w: empty tag not allowed", shared.ErrValidation)
		}
		if len(tag) > 200 {
			return fmt.Errorf("%w: tag exceeds maximum length of 200 characters", shared.ErrValidation)
		}
	}
	if !logic.IsValid() {
		return fmt.Errorf("%w: invalid match logic", shared.ErrValidation)
	}
	r.matchTags = tags
	r.matchLogic = logic
	r.updatedAt = time.Now().UTC()
	return nil
}

func (r *ScopeRule) SetMatchAssetGroupIDs(ids []shared.ID) error {
	if r.ruleType != ScopeRuleAssetGroupMatch {
		return fmt.Errorf("%w: match_asset_group_ids only valid for asset_group_match rules", shared.ErrValidation)
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: at least one asset group is required", shared.ErrValidation)
	}
	if len(ids) > MaxMatchAssetGroups {
		return fmt.Errorf("%w: maximum %d asset groups per rule", shared.ErrValidation, MaxMatchAssetGroups)
	}
	r.matchAssetGroupIDs = ids
	r.updatedAt = time.Now().UTC()
	return nil
}

func (r *ScopeRule) SetOwnershipType(t OwnershipType) error {
	if !t.IsValid() {
		return fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)
	}
	r.ownershipType = t
	r.updatedAt = time.Now().UTC()
	return nil
}

func (r *ScopeRule) SetPriority(priority int) {
	r.priority = priority
	r.updatedAt = time.Now().UTC()
}

func (r *ScopeRule) Activate() {
	r.isActive = true
	r.updatedAt = time.Now().UTC()
}

func (r *ScopeRule) Deactivate() {
	r.isActive = false
	r.updatedAt = time.Now().UTC()
}
