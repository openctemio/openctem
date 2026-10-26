package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// orgTools is a tool registry holding organization tools; it filters by
// tenant like the repository and counts its queries.
type orgTools struct {
	tool.Repository
	custom  []*tool.Tool
	err     error
	queries int
}

func (o *orgTools) ListTenantCustomTools(_ context.Context, tenantID shared.ID, _ tool.ToolFilter, _ pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	o.queries++
	if o.err != nil {
		return pagination.Result[*tool.Tool]{}, o.err
	}
	var out []*tool.Tool
	for _, t := range o.custom {
		if t.TenantID != nil && *t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return pagination.Result[*tool.Tool]{Data: out}, nil
}

func declared(t *testing.T, tenantID shared.ID, name, ref string) *tool.Tool {
	t.Helper()
	dt, err := tool.NewDeclaredTool(tenantID, tool.Declaration{Name: name, Version: "1.0.0", Implements: []string{ref}, Digest: "sha256:" + name})
	if err != nil {
		t.Fatal(err)
	}
	return dt
}

// A prefer list may name the organization's declared tool that implements
// the step's capability; one that implements another capability, another
// organization's tool and an unknown name are refused.
func TestCheckStepSelection_DeclaredToolsInPreferList(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	repo := &orgTools{custom: []*tool.Tool{
		declared(t, tenant, "acme-headers", "vuln.templates@1"),
		declared(t, tenant, "acme-dast", "dast.web@1"),
		declared(t, other, "globex-checks", "vuln.templates@1"),
	}}
	s := &Service{toolRepo: repo}
	step := func(prefer ...string) *scanworkflow.Step {
		return &scanworkflow.Step{StepKey: "vulns", Capabilities: []string{"vuln.templates"}, PreferTools: prefer}
	}
	cases := []struct {
		prefer []string
		ok     bool
	}{
		{[]string{"acme-headers", "nuclei"}, true},
		{[]string{"nuclei"}, true},
		{[]string{"acme-dast"}, false},     // implements another capability
		{[]string{"globex-checks"}, false}, // another organization's
		{[]string{"nope"}, false},
	}
	for _, tc := range cases {
		d, err := s.declaredToolsFor(context.Background(), tenant, tc.prefer)
		if err != nil {
			t.Fatal(err)
		}
		err = checkStepSelection(step(tc.prefer...), d)
		if tc.ok != (err == nil) {
			t.Errorf("prefer %v: err = %v, want ok=%v", tc.prefer, err, tc.ok)
		}
		if err != nil && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("prefer %v: err = %v, want a validation error", tc.prefer, err)
		}
	}
}

// A prefer list of catalog tools only reads nothing; a failed read is an
// error, never "no declared tools".
func TestDeclaredToolsFor_QueriesOnlyWhenNeeded(t *testing.T) {
	repo := &orgTools{}
	s := &Service{toolRepo: repo}
	if d, err := s.declaredToolsFor(context.Background(), shared.NewID(), []string{"nuclei", "httpx"}); err != nil || d != nil || repo.queries != 0 {
		t.Fatalf("catalog-only prefer list: %v %v, %d queries", d, err, repo.queries)
	}
	repo.err = errors.New("db down")
	if _, err := s.declaredToolsFor(context.Background(), shared.NewID(), []string{"acme-headers"}); err == nil {
		t.Fatal("a failed read was not reported")
	}
}
