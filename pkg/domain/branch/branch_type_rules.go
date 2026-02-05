package branch

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
)

// BranchTypeRule maps a branch name pattern to a branch type.
// Pattern can be matched exactly (e.g., "main" -> TypeMain) or by prefix (e.g., "feat/" -> TypeFeature).
type BranchTypeRule struct {
	Pattern    string `json:"pattern"`     // e.g., "feat/", "main", "dev/"
	MatchType  string `json:"match_type"`  // "exact" or "prefix"
	BranchType Type   `json:"branch_type"` // one of the six valid types
}

// BranchTypeRules is an ordered list of rules. First match wins.
type BranchTypeRules []BranchTypeRule

const maxBranchTypeRules = 50

// Validate checks that all rules have valid fields.
func (rules BranchTypeRules) Validate() error {
	if len(rules) > maxBranchTypeRules {
		return fmt.Errorf("%w: too many branch type rules (max %d)", shared.ErrValidation, maxBranchTypeRules)
	}
	for i, r := range rules {
		if r.Pattern == "" {
			return fmt.Errorf("%w: rule %d: pattern is required", shared.ErrValidation, i)
		}
		if len(r.Pattern) > 100 {
			return fmt.Errorf("%w: rule %d: pattern too long (max 100 chars)", shared.ErrValidation, i)
		}
		if r.MatchType != "exact" && r.MatchType != "prefix" {
			return fmt.Errorf("%w: rule %d: match_type must be 'exact' or 'prefix'", shared.ErrValidation, i)
		}
		if !r.BranchType.IsValid() || r.BranchType == TypeOther {
			return fmt.Errorf("%w: rule %d: branch_type must be one of: main, develop, feature, release, hotfix", shared.ErrValidation, i)
		}
	}
	return nil
}

// Detect applies rules to a branch name and returns the first matching type.
// Returns TypeOther if no rule matches.
func (rules BranchTypeRules) Detect(branchName string) Type {
	for _, r := range rules {
		switch r.MatchType {
		case "exact":
			if branchName == r.Pattern {
				return r.BranchType
			}
		case "prefix":
			if strings.HasPrefix(branchName, r.Pattern) {
				return r.BranchType
			}
		}
	}
	return TypeOther
}

// DefaultBranchTypeRules returns the system default rules,
// equivalent to the previous hardcoded detection logic.
func DefaultBranchTypeRules() BranchTypeRules {
	return BranchTypeRules{
		// Exact matches
		{Pattern: "main", MatchType: "exact", BranchType: TypeMain},
		{Pattern: "master", MatchType: "exact", BranchType: TypeMain},
		{Pattern: "develop", MatchType: "exact", BranchType: TypeDevelop},
		{Pattern: "development", MatchType: "exact", BranchType: TypeDevelop},
		{Pattern: "dev", MatchType: "exact", BranchType: TypeDevelop},
		// Prefix matches
		{Pattern: "feature/", MatchType: "prefix", BranchType: TypeFeature},
		{Pattern: "release/", MatchType: "prefix", BranchType: TypeRelease},
		{Pattern: "hotfix/", MatchType: "prefix", BranchType: TypeHotfix},
	}
}

// DetectBranchType resolves branch type using the fallback chain:
// per-asset rules > per-tenant rules > system defaults.
// Each level is an ordered list of rules; first match within a level wins.
// If a level has rules but none match, it falls through to the next level.
func DetectBranchType(branchName string, assetRules, tenantRules BranchTypeRules) Type {
	// Level 1: per-asset rules
	if len(assetRules) > 0 {
		if t := assetRules.Detect(branchName); t != TypeOther {
			return t
		}
	}
	// Level 2: per-tenant rules
	if len(tenantRules) > 0 {
		if t := tenantRules.Detect(branchName); t != TypeOther {
			return t
		}
	}
	// Level 3: system defaults
	return DefaultBranchTypeRules().Detect(branchName)
}

// ParseRulesFromProperties extracts BranchTypeRules from an asset's properties map.
// Returns nil if not present or invalid.
func ParseRulesFromProperties(properties map[string]any) BranchTypeRules {
	raw, ok := properties["branch_type_rules"]
	if !ok || raw == nil {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var rules BranchTypeRules
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil
	}
	if err := rules.Validate(); err != nil {
		return nil
	}
	return rules
}
