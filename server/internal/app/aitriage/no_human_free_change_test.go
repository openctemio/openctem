package aitriage

// AI triage results are suggestions. A person must make any change to a
// finding's severity or priority, so the triage service never writes them
// itself. See docs/architecture/ai-triage.md.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// writeRecordingFindings fails the test on any write to the finding store.
// The embedded fakeFindings panics on every other method, so an unexpected
// call also fails the test.
type writeRecordingFindings struct {
	fakeFindings
	mu    sync.Mutex
	calls []string
}

func (w *writeRecordingFindings) record(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, name)
}

func (w *writeRecordingFindings) Update(context.Context, *vulnerability.Finding) error {
	w.record("Update")
	return nil
}

func (w *writeRecordingFindings) UpdateStatusBatch(context.Context, shared.ID, []shared.ID, vulnerability.FindingStatus, string, *shared.ID, vulnerability.Closure) error {
	w.record("UpdateStatusBatch")
	return nil
}

func (w *writeRecordingFindings) BulkUpdateStatusByFilter(context.Context, shared.ID, vulnerability.FindingFilter, vulnerability.FindingStatus, string, *shared.ID, vulnerability.Closure) (int64, error) {
	w.record("BulkUpdateStatusByFilter")
	return 0, nil
}

// A model that proposes a critical severity, the top priority and a near
// certain false positive changes nothing on the finding: the answer is stored
// on the triage result for a person to review.
func TestAITriage_ModelCannotChangeSeverityOrPriority(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	rec := &writeRecordingFindings{fakeFindings: fakeFindings{byID: h.findings}}
	h.svc.findingRepo = rec

	h.llm.resp = `{"severity_assessment":"critical","severity_justification":"j","risk_score":99,
"exploitability":"high","exploitability_details":"d","business_impact":"b","false_positive_likelihood":0.99,
"false_positive_reason":"looks fine","priority_rank":1,"remediation_steps":[],"related_cves":[],"related_cwes":[],"summary":"s"}`

	f, err := vulnerability.NewFinding(h.tenantID, shared.NewID(), vulnerability.FindingSourceSAST, "tool", vulnerability.SeverityLow, "msg")
	require.NoError(t, err)
	f.SetTitle("Verbose error message")
	h.findings[f.ID()] = f

	priorityBefore := f.PriorityClass()
	reasonBefore := f.PriorityClassReason()
	statusBefore := f.Status()

	row := h.pendingRow(t, f)
	require.NoError(t, h.svc.ProcessTriage(ctx, row.ID(), h.tenantID, f.ID()))
	require.Equal(t, aitriagedom.TriageStatusCompleted, row.Status())
	require.Equal(t, "critical", row.SeverityAssessment(), "the suggestion is kept on the triage result")

	stored := h.findings[f.ID()]
	require.Equal(t, vulnerability.SeverityLow, stored.Severity())
	require.False(t, stored.HasSeverityOverride())
	require.Nil(t, stored.SeverityOverride())
	require.Equal(t, vulnerability.SeverityLow, stored.SourceSeverity())
	require.Equal(t, priorityBefore, stored.PriorityClass())
	require.Equal(t, reasonBefore, stored.PriorityClassReason())
	require.False(t, stored.PriorityClassOverride())
	require.Nil(t, stored.PriorityClassOverriddenBy())
	require.Equal(t, statusBefore, stored.Status())
	require.Empty(t, rec.calls, "triage must not write to the finding store")
}

// The triage package must not call a method that changes severity or priority.
// A person makes such a change; the model only suggests.
func TestAITriage_NoSeverityOrPriorityWriteInPackage(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, err)
		checked++
		for _, bad := range forbiddenSeverityPriorityCalls(file) {
			t.Errorf("%s: %s calls %s; severity and priority changes need a person, not AI triage",
				name, fset.Position(bad.pos), bad.name)
		}
	}
	require.NotZero(t, checked)
}

type badCall struct {
	name string
	pos  token.Pos
}

func isForbiddenSeverityPriorityCall(name string) bool {
	switch name {
	case "UpdateSeverity", "SetSeverityOverride", "SetPriorityClassification", "OverridePriorityClass", "RestoreSourceSeverity":
		return true
	}
	writes := strings.HasPrefix(name, "Update") || strings.HasPrefix(name, "Set") || strings.HasPrefix(name, "Bulk")
	return writes && (strings.Contains(name, "Severity") || strings.Contains(name, "Priority"))
}

func forbiddenSeverityPriorityCalls(file *ast.File) []badCall {
	var out []badCall
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isForbiddenSeverityPriorityCall(sel.Sel.Name) {
			out = append(out, badCall{name: sel.Sel.Name, pos: call.Pos()})
		}
		return true
	})
	return out
}

// The guard itself catches the calls it is meant to catch.
func TestAITriage_SeverityPriorityGuardDetects(t *testing.T) {
	src := `package x
func f() {
	finding.SetSeverityOverride(a, b, c, d)
	repo.UpdateSeverity(ctx, id)
	repo.BulkUpdatePriorityClass(ctx, ids)
	finding.SetPriorityClassification(x, y)
	finding.Severity()
	repo.UpdateStatusBatch()
}`
	file, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	require.NoError(t, err)
	var names []string
	for _, b := range forbiddenSeverityPriorityCalls(file) {
		names = append(names, b.name)
	}
	require.Equal(t, []string{"SetSeverityOverride", "UpdateSeverity", "BulkUpdatePriorityClass", "SetPriorityClassification"}, names)
}
