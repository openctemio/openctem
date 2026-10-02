package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/branch"
)

func TestBranchTypeRules_Detect(t *testing.T) {
	rules := branch.BranchTypeRules{
		{Pattern: "main", MatchType: "exact", BranchType: branch.TypeMain},
		{Pattern: "feat/", MatchType: "prefix", BranchType: branch.TypeFeature},
		{Pattern: "fix/", MatchType: "prefix", BranchType: branch.TypeHotfix},
	}

	tests := []struct {
		name     string
		branch   string
		expected branch.Type
	}{
		{"exact match", "main", branch.TypeMain},
		{"prefix match feature", "feat/login", branch.TypeFeature},
		{"prefix match hotfix", "fix/crash", branch.TypeHotfix},
		{"no match", "release/v1", branch.TypeOther},
		{"partial exact no match", "main-backup", branch.TypeOther},
		{"empty name", "", branch.TypeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rules.Detect(tt.branch)
			if got != tt.expected {
				t.Errorf("Detect(%q) = %q, want %q", tt.branch, got, tt.expected)
			}
		})
	}
}

func TestBranchTypeRules_Detect_EmptyRules(t *testing.T) {
	var rules branch.BranchTypeRules
	if got := rules.Detect("main"); got != branch.TypeOther {
		t.Errorf("empty rules.Detect(main) = %q, want TypeOther", got)
	}
}

func TestBranchTypeRules_Detect_FirstMatchWins(t *testing.T) {
	rules := branch.BranchTypeRules{
		{Pattern: "dev/", MatchType: "prefix", BranchType: branch.TypeDevelop},
		{Pattern: "dev/", MatchType: "prefix", BranchType: branch.TypeFeature}, // should never match
	}

	got := rules.Detect("dev/john/login")
	if got != branch.TypeDevelop {
		t.Errorf("first-match: got %q, want TypeDevelop", got)
	}
}

func TestDefaultBranchTypeRules(t *testing.T) {
	defaults := branch.DefaultBranchTypeRules()

	tests := []struct {
		name     string
		branch   string
		expected branch.Type
	}{
		{"main", "main", branch.TypeMain},
		{"master", "master", branch.TypeMain},
		{"develop", "develop", branch.TypeDevelop},
		{"development", "development", branch.TypeDevelop},
		{"dev", "dev", branch.TypeDevelop},
		{"feature/xxx", "feature/add-login", branch.TypeFeature},
		{"release/xxx", "release/v1.0.0", branch.TypeRelease},
		{"hotfix/xxx", "hotfix/fix-bug", branch.TypeHotfix},
		{"unknown", "random-branch", branch.TypeOther},
		{"feat/ not default", "feat/login", branch.TypeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaults.Detect(tt.branch)
			if got != tt.expected {
				t.Errorf("defaults.Detect(%q) = %q, want %q", tt.branch, got, tt.expected)
			}
		})
	}
}

func TestDetectBranchType_FallbackChain(t *testing.T) {
	tenantRules := branch.BranchTypeRules{
		{Pattern: "feat/", MatchType: "prefix", BranchType: branch.TypeFeature},
		{Pattern: "fix/", MatchType: "prefix", BranchType: branch.TypeHotfix},
	}

	assetRules := branch.BranchTypeRules{
		{Pattern: "dev/", MatchType: "prefix", BranchType: branch.TypeDevelop},
	}

	tests := []struct {
		name        string
		branchName  string
		assetRules  branch.BranchTypeRules
		tenantRules branch.BranchTypeRules
		expected    branch.Type
	}{
		{
			name:        "asset rule matches first",
			branchName:  "dev/john/login",
			assetRules:  assetRules,
			tenantRules: tenantRules,
			expected:    branch.TypeDevelop,
		},
		{
			name:        "tenant rule matches when no asset match",
			branchName:  "feat/login",
			assetRules:  assetRules,
			tenantRules: tenantRules,
			expected:    branch.TypeFeature,
		},
		{
			name:        "system default matches when no tenant/asset match",
			branchName:  "main",
			assetRules:  assetRules,
			tenantRules: tenantRules,
			expected:    branch.TypeMain,
		},
		{
			name:        "system default feature/ prefix",
			branchName:  "feature/new-thing",
			assetRules:  nil,
			tenantRules: nil,
			expected:    branch.TypeFeature,
		},
		{
			name:        "nil rules fall through to defaults",
			branchName:  "hotfix/urgent",
			assetRules:  nil,
			tenantRules: nil,
			expected:    branch.TypeHotfix,
		},
		{
			name:        "tenant overrides system default prefix",
			branchName:  "fix/crash",
			assetRules:  nil,
			tenantRules: tenantRules,
			expected:    branch.TypeHotfix,
		},
		{
			name:        "no rules match anywhere returns Other",
			branchName:  "random/branch",
			assetRules:  assetRules,
			tenantRules: tenantRules,
			expected:    branch.TypeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := branch.DetectBranchType(tt.branchName, tt.assetRules, tt.tenantRules)
			if got != tt.expected {
				t.Errorf("DetectBranchType(%q) = %q, want %q", tt.branchName, got, tt.expected)
			}
		})
	}
}

func TestBranchTypeRules_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rules   branch.BranchTypeRules
		wantErr bool
	}{
		{
			name:    "valid rules",
			rules:   branch.BranchTypeRules{{Pattern: "feat/", MatchType: "prefix", BranchType: branch.TypeFeature}},
			wantErr: false,
		},
		{
			name:    "empty rules valid",
			rules:   branch.BranchTypeRules{},
			wantErr: false,
		},
		{
			name:    "nil rules valid",
			rules:   nil,
			wantErr: false,
		},
		{
			name:    "empty pattern",
			rules:   branch.BranchTypeRules{{Pattern: "", MatchType: "prefix", BranchType: branch.TypeFeature}},
			wantErr: true,
		},
		{
			name:    "invalid match type",
			rules:   branch.BranchTypeRules{{Pattern: "feat/", MatchType: "glob", BranchType: branch.TypeFeature}},
			wantErr: true,
		},
		{
			name:    "TypeOther not allowed",
			rules:   branch.BranchTypeRules{{Pattern: "test/", MatchType: "prefix", BranchType: branch.TypeOther}},
			wantErr: true,
		},
		{
			name:    "invalid branch type",
			rules:   branch.BranchTypeRules{{Pattern: "test/", MatchType: "prefix", BranchType: branch.Type("invalid")}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rules.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRulesFromProperties(t *testing.T) {
	t.Run("valid rules in properties", func(t *testing.T) {
		props := map[string]any{
			"branch_type_rules": []any{
				map[string]any{
					"pattern":     "feat/",
					"match_type":  "prefix",
					"branch_type": "feature",
				},
			},
		}

		rules := branch.ParseRulesFromProperties(props)
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}
		if rules[0].Pattern != "feat/" {
			t.Errorf("pattern = %q, want feat/", rules[0].Pattern)
		}
	})

	t.Run("missing key returns nil", func(t *testing.T) {
		props := map[string]any{"other": "value"}
		rules := branch.ParseRulesFromProperties(props)
		if rules != nil {
			t.Errorf("expected nil, got %v", rules)
		}
	})

	t.Run("nil properties returns nil", func(t *testing.T) {
		rules := branch.ParseRulesFromProperties(nil)
		if rules != nil {
			t.Errorf("expected nil, got %v", rules)
		}
	})

	t.Run("invalid data returns nil", func(t *testing.T) {
		props := map[string]any{"branch_type_rules": "not an array"}
		rules := branch.ParseRulesFromProperties(props)
		if rules != nil {
			t.Errorf("expected nil for invalid data, got %v", rules)
		}
	})
}
