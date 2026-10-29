package tenantai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeMaskingRepo struct {
	byTenant map[shared.ID]tenant.AIMaskingPolicy
}

func (f *fakeMaskingRepo) GetMasking(_ context.Context, id shared.ID) (tenant.AIMaskingPolicy, error) {
	return f.byTenant[id], nil
}

func (f *fakeMaskingRepo) SaveMasking(_ context.Context, id shared.ID, p tenant.AIMaskingPolicy) error {
	f.byTenant[id] = p
	return nil
}

// fakeScopedFindings answers like GetFindingWithScope: another tenant's
// finding or one outside the caller's scope is not found.
type fakeScopedFindings struct {
	byID    map[string]*vulnerability.Finding
	inScope map[string]bool
}

func (f fakeScopedFindings) GetFindingWithScope(_ context.Context, tenantID, findingID, _ string, isAdmin bool) (*vulnerability.Finding, error) {
	v, ok := f.byID[findingID]
	if !ok || v.TenantID().String() != tenantID || (!isAdmin && !f.inScope[findingID]) {
		return nil, shared.ErrNotFound
	}
	return v, nil
}

func maskingFixture(t *testing.T) (*MaskingService, *fakeMaskingRepo, shared.ID, shared.ID, *vulnerability.Finding, *vulnerability.Finding) {
	t.Helper()
	tA, tB := shared.NewID(), shared.NewID()
	mk := func(tid shared.ID, src vulnerability.FindingSource) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tid, shared.NewID(), src, "nuclei", vulnerability.SeverityHigh, "m")
		if err != nil {
			t.Fatal(err)
		}
		f.SetTitle("Admin panel on portal.example.com from 10.1.2.3")
		return f
	}
	fA, fB := mk(tA, vulnerability.FindingSourceDAST), mk(tB, vulnerability.FindingSourceDAST)
	repo := &fakeMaskingRepo{byTenant: map[shared.ID]tenant.AIMaskingPolicy{}}
	findings := fakeScopedFindings{byID: map[string]*vulnerability.Finding{fA.ID().String(): fA, fB.ID().String(): fB}, inScope: map[string]bool{}}
	return NewMaskingService(repo, findings, nil, nil, aibundle.NewBuilder(nil), nil, nil), repo, tA, tB, fA, fB
}

func TestMasking_DefaultsAndSave(t *testing.T) {
	s, repo, tA, tB, _, _ := maskingFixture(t)
	ctx := context.Background()
	v, err := s.GetMasking(ctx, tA.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Classes {
		if !c.Masked {
			t.Fatalf("default must mask every class, %s is off", c.Class)
		}
	}
	v, err = s.SaveMasking(ctx, tA.String(), MaskingUpdate{Off: []string{"ips", "ips"}, Terms: []string{" Project Falcon ", "project falcon"}},
		auditapp.AuditContext{ActorID: shared.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Terms) != 1 || v.Terms[0] != "Project Falcon" {
		t.Fatalf("terms not normalised: %v", v.Terms)
	}
	if repo.byTenant[tA].Masked(tenant.AIMaskIPs) {
		t.Fatal("ips should be off")
	}
	// Tenant B is untouched.
	if len(repo.byTenant[tB].Off) != 0 {
		t.Fatal("another organization's policy changed")
	}
	if _, err := s.SaveMasking(ctx, tA.String(), MaskingUpdate{Off: []string{"secrets"}}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("secrets must not be configurable: %v", err)
	}
	if _, err := s.SaveMasking(ctx, tA.String(), MaskingUpdate{Terms: []string{"ab"}}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("short term accepted: %v", err)
	}
}

func TestMasking_Loosens(t *testing.T) {
	base := tenant.AIMaskingPolicy{Terms: []string{"Acme"}, MaskSubdomainLabels: true}
	for name, next := range map[string]tenant.AIMaskingPolicy{
		"class off":    {Terms: []string{"Acme"}, MaskSubdomainLabels: true, Off: []tenant.AIMaskClass{tenant.AIMaskHosts}},
		"labels off":   {Terms: []string{"Acme"}},
		"term removed": {MaskSubdomainLabels: true},
	} {
		if !base.Loosens(next) {
			t.Errorf("%s: not reported as loosening", name)
		}
	}
	if base.Loosens(tenant.AIMaskingPolicy{Terms: []string{"acme", "Beta"}, MaskSubdomainLabels: true}) {
		t.Error("adding a term is not loosening")
	}
}

func TestMasking_PreviewIsolationAndNoValues(t *testing.T) {
	s, _, tA, _, fA, fB := maskingFixture(t)
	ctx := context.Background()
	p, err := s.PreviewMasking(ctx, PreviewInput{TenantID: tA.String(), FindingID: fA.ID().String(), IsAdmin: true}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Text, "portal.example.com") || strings.Contains(p.Text, "10.1.2.3") {
		t.Fatalf("preview leaks a real value:\n%s", p.Text)
	}
	if len(p.Placeholders) == 0 || p.DataClass != string(aipolicy.ClassInternal) {
		t.Fatalf("placeholders %v class %s", p.Placeholders, p.DataClass)
	}
	for _, ph := range p.Placeholders {
		if strings.Contains(ph.Token, "example") || strings.Contains(ph.Token, "10.1") {
			t.Fatalf("placeholder carries a value: %v", ph)
		}
	}
	// Another organization's finding, by id guessing: not found.
	if _, err := s.PreviewMasking(ctx, PreviewInput{TenantID: tA.String(), FindingID: fB.ID().String(), IsAdmin: true}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant preview: %v", err)
	}
	// Outside the caller's data scope: not found.
	if _, err := s.PreviewMasking(ctx, PreviewInput{TenantID: tA.String(), FindingID: fA.ID().String(), IsAdmin: false}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope preview: %v", err)
	}
	// tenant_only is never a preview ceiling.
	if _, err := s.PreviewMasking(ctx, PreviewInput{TenantID: tA.String(), FindingID: fA.ID().String(), IsAdmin: true, DataClass: "tenant_only"}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tenant_only ceiling accepted: %v", err)
	}
}

func TestMasking_PreviewRefusedByEgressPolicy(t *testing.T) {
	s, _, tA, _, _, _ := maskingFixture(t)
	f, err := vulnerability.NewFinding(tA, shared.NewID(), vulnerability.FindingSourcePentest, "manual", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	s.findings.(fakeScopedFindings).byID[f.ID().String()] = f
	_, err = s.PreviewMasking(context.Background(), PreviewInput{TenantID: tA.String(), FindingID: f.ID().String(), IsAdmin: true}, auditapp.AuditContext{})
	if !errors.Is(err, aipolicy.ErrRestricted) {
		t.Fatalf("a pentest finding without an allowed campaign was previewed: %v", err)
	}
}
