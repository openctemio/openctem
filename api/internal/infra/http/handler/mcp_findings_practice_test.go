package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// list_findings passes practice, exclude_practice and compliance_result to the
// findings list's own parser, which refuses unknown values.
func TestMCPListFindingsPracticeArgs(t *testing.T) {
	q, err := findingListArgs{Practice: "ASPM,infra", ExclPractice: "compliance", ComplianceRes: "fail"}.values()
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("practice") != "aspm,infra" || q.Get("practice_not") != "compliance" || q.Get("compliance_result") != "fail" {
		t.Fatalf("values = %v", q)
	}
	if _, err := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict}); err != nil {
		t.Fatalf("the findings registry refused the practice params: %v", err)
	}
	bad, _ := findingListArgs{Practice: "vulns"}.values()
	if _, err := filterspec.ParseValues(bad, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict}); err == nil || !strings.Contains(err.Error(), "practice") {
		t.Fatalf("an unknown practice must be refused, got %v", err)
	}
	if !strings.Contains(mcpFindingListSchema, `"exclude_practice"`) {
		t.Fatal("list_findings schema does not document exclude_practice")
	}
}
