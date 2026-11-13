package main

import (
	"strings"
	"testing"
)

// =============================================================================
// validate() tests
// =============================================================================
//
// These tests pin down the validation rules so a future refactor of the
// codegen tool can't accidentally weaken them. Each error path has a
// dedicated test case so the failure mode is clear when one regresses.

func validConfig() *config {
	return &config{
		Categories: []category{
			{ID: "cat1", Name: "Category One"},
		},
		Types: []relType{
			{
				ID:          "type_one",
				Category:    "cat1",
				Direct:      "Type One",
				Inverse:     "Reversed One",
				Description: "First type",
				Constraints: []constraint{
					{Sources: []string{"host"}, Targets: []string{"service"}},
				},
			},
		},
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := validate(validConfig()); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
}

func TestValidate_RejectsEmptyCategories(t *testing.T) {
	cfg := validConfig()
	cfg.Categories = nil
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty categories")
	}
	if !strings.Contains(err.Error(), "no categories") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsEmptyTypes(t *testing.T) {
	cfg := validConfig()
	cfg.Types = nil
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty types")
	}
	if !strings.Contains(err.Error(), "no types") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsCategoryWithEmptyID(t *testing.T) {
	cfg := validConfig()
	cfg.Categories = append(cfg.Categories, category{ID: "", Name: "Bad"})
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty category id")
	}
	if !strings.Contains(err.Error(), "empty id") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsCategoryWithEmptyName(t *testing.T) {
	cfg := validConfig()
	cfg.Categories = append(cfg.Categories, category{ID: "bad", Name: ""})
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty category name")
	}
}

func TestValidate_RejectsDuplicateCategoryID(t *testing.T) {
	cfg := validConfig()
	cfg.Categories = append(cfg.Categories, category{ID: "cat1", Name: "Duplicate"})
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for duplicate category id")
	}
	if !strings.Contains(err.Error(), "duplicate category id") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsTypeWithEmptyID(t *testing.T) {
	cfg := validConfig()
	cfg.Types = append(cfg.Types, relType{
		ID:          "",
		Category:    "cat1",
		Direct:      "X",
		Inverse:     "Y",
		Constraints: []constraint{{Sources: []string{"a"}, Targets: []string{"b"}}},
	})
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty type id")
	}
}

func TestValidate_RejectsDuplicateTypeID(t *testing.T) {
	cfg := validConfig()
	cfg.Types = append(cfg.Types, relType{
		ID:          "type_one",
		Category:    "cat1",
		Direct:      "Dup",
		Inverse:     "Dup",
		Constraints: []constraint{{Sources: []string{"a"}, Targets: []string{"b"}}},
	})
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for duplicate type id")
	}
	if !strings.Contains(err.Error(), "duplicate type id") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsTypeReferencingUnknownCategory(t *testing.T) {
	cfg := validConfig()
	cfg.Types[0].Category = "does_not_exist"
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for unknown category reference")
	}
	if !strings.Contains(err.Error(), "unknown category") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsTypeWithEmptyLabels(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *relType)
		errFrag string
	}{
		{
			name:    "empty direct",
			mutate:  func(t *relType) { t.Direct = "" },
			errFrag: "empty direct or inverse",
		},
		{
			name:    "empty inverse",
			mutate:  func(t *relType) { t.Inverse = "" },
			errFrag: "empty direct or inverse",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg.Types[0])
			err := validate(cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_RejectsTypeWithNoConstraints(t *testing.T) {
	cfg := validConfig()
	cfg.Types[0].Constraints = nil
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for missing constraints")
	}
	if !strings.Contains(err.Error(), "no constraints") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsConstraintWithEmptySources(t *testing.T) {
	cfg := validConfig()
	cfg.Types[0].Constraints[0].Sources = nil
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty constraint sources")
	}
	if !strings.Contains(err.Error(), "empty sources or targets") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RejectsConstraintWithEmptyTargets(t *testing.T) {
	cfg := validConfig()
	cfg.Types[0].Constraints[0].Targets = nil
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty constraint targets")
	}
	if !strings.Contains(err.Error(), "empty sources or targets") {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestToCamel(t *testing.T) {
	cases := map[string]string{
		"runs_on":       "RunsOn",
		"sends_data_to": "SendsDataTo",
		"k8s_workload":  "K8sWorkload",
		"single":        "Single",
		"":              "",
		"a_b_c_d_e":     "ABCDE",
	}
	for in, want := range cases {
		got := toCamel(in)
		if got != want {
			t.Errorf("toCamel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoStringList(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{in: []string{"a"}, want: `"a"`},
		{in: []string{"a", "b"}, want: `"a", "b"`},
		{in: []string{}, want: ""},
		{in: []string{"with space"}, want: `"with space"`},
	}
	for _, tc := range cases {
		got := goStringList(tc.in)
		if got != tc.want {
			t.Errorf("goStringList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTSStringList(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{in: []string{"a"}, want: `'a'`},
		{in: []string{"a", "b"}, want: `'a', 'b'`},
		{in: []string{}, want: ""},
	}
	for _, tc := range cases {
		got := tsStringList(tc.in)
		if got != tc.want {
			t.Errorf("tsStringList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTrimDesc_CollapsesMultilineYAMLFolded(t *testing.T) {
	cases := map[string]string{
		"single line":          "single line",
		"line one\nline two":   "line one line two",
		"  leading and trail ": "leading and trail",
		"multiple    spaces":   "multiple spaces",
		"":                     "",
		// YAML folded scalar produces this kind of input
		"Runtime location of\na workload —\nservice runs on compute.": "Runtime location of a workload — service runs on compute.",
	}
	for in, want := range cases {
		got := trimDesc(in)
		if got != want {
			t.Errorf("trimDesc(%q) = %q, want %q", in, got, want)
		}
	}
}

// =============================================================================
// Real-world canonical YAML loads cleanly
// =============================================================================
//
// This test pins the production YAML — if a future edit produces a
// config that fails validation, this test catches it before the file
// hits CI. It does NOT verify the contents (that would duplicate the
// YAML); it only verifies the file is parseable + valid.

func TestProductionYAML_LoadsAndValidates(t *testing.T) {
	cfg, err := loadConfig("../../configs/relationship-types.yaml")
	if err != nil {
		t.Fatalf("load production yaml: %v", err)
	}
	if err := validate(cfg); err != nil {
		t.Fatalf("validate production yaml: %v", err)
	}
	if len(cfg.Categories) == 0 {
		t.Fatal("expected at least one category in production yaml")
	}
	if len(cfg.Types) == 0 {
		t.Fatal("expected at least one type in production yaml")
	}
	// Sanity: every type's category must resolve to a real entry.
	categoryIDs := make(map[string]bool, len(cfg.Categories))
	for _, c := range cfg.Categories {
		categoryIDs[c.ID] = true
	}
	for _, ty := range cfg.Types {
		if !categoryIDs[ty.Category] {
			t.Errorf("type %q references unknown category %q", ty.ID, ty.Category)
		}
	}
}
