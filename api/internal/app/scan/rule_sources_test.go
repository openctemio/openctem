package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenantTemplates is a scanner template store that, like the postgres one,
// returns only the asking tenant's templates.
type tenantTemplates struct {
	scannertemplate.Repository
	byTenant map[shared.ID][]*scannertemplate.ScannerTemplate
	err      error
}

func (r *tenantTemplates) ListByIDs(_ context.Context, tenantID shared.ID, ids []shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []*scannertemplate.ScannerTemplate
	for _, t := range r.byTenant[tenantID] {
		if slices.ContainsFunc(ids, func(id shared.ID) bool { return id.Equals(t.ID) }) {
			out = append(out, t)
		}
	}
	return out, nil
}

// tenantProfiles answers GetAccessibleByID within the tenant only.
type tenantProfiles struct {
	scanprofile.Repository
	byID map[shared.ID]*scanprofile.ScanProfile
	err  error
}

func (r *tenantProfiles) GetAccessibleByID(_ context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	if r.err != nil {
		return nil, r.err
	}
	p, ok := r.byID[id]
	if !ok || !p.TenantID.Equals(tenantID) {
		return nil, shared.ErrNotFound
	}
	return p, nil
}

func ruleTemplate(tenant shared.ID, name, body string, status scannertemplate.TemplateStatus) *scannertemplate.ScannerTemplate {
	return &scannertemplate.ScannerTemplate{ID: shared.NewID(), TenantID: tenant, Name: name,
		TemplateType: scannertemplate.TemplateTypeNuclei, Content: []byte(body), ContentHash: "h-" + name, Status: status}
}

// rulePayload is what a test reads back from a created command.
type rulePayload struct {
	RuleSources      string             `json:"rule_sources"`
	RequiredFeatures []string           `json:"required_features"`
	CustomTemplates  []EmbeddedTemplate `json:"custom_templates"`
}

func ruleSourcesService(templates *tenantTemplates, profiles *tenantProfiles) (*Service, *createdCommands) {
	svc := splitGate(&tenantExclusionRepo{}, nil)
	cmds := &createdCommands{}
	svc.commandRepo = cmds
	svc.scannerTemplateRepo = templates
	if profiles != nil {
		svc.profileRepo = profiles
	}
	return svc, cmds
}

func nucleiScan(tenant shared.ID, ids ...shared.ID) *scan.Scan {
	cfg := map[string]any{}
	if len(ids) > 0 {
		raw := make([]any, 0, len(ids))
		for _, id := range ids {
			raw = append(raw, id.String())
		}
		cfg["custom_template_ids"] = raw
	}
	return &scan.Scan{ID: shared.NewID(), TenantID: tenant, Name: "s", ScanType: scan.ScanTypeSingle, ScannerName: "nuclei", ScannerConfig: cfg}
}

// dispatch resolves the rule sources like the trigger and creates the
// command; it returns the created payload, or the error.
func dispatch(t *testing.T, svc *Service, cmds *createdCommands, sc *scan.Scan) (rulePayload, error) {
	t.Helper()
	rs, err := svc.applyRuleSourcesAtTrigger(context.Background(), sc)
	if err != nil {
		return rulePayload{}, err
	}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: sc.TenantID, Context: map[string]any{RunContextKeyRuleSources: string(rs)}}
	before := len(cmds.cmds)
	if err := svc.createScannerCommand(context.Background(), sc, run, nil, []string{"https://203.0.113.10"}, false); err != nil {
		if len(cmds.cmds) != before {
			t.Fatal("a failed dispatch created a command")
		}
		return rulePayload{}, err
	}
	var p rulePayload
	if err := json.Unmarshal(cmds.cmds[len(cmds.cmds)-1].Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p, nil
}

func TestRuleSources_EachChoiceShapesTheCommand(t *testing.T) {
	tenant := shared.NewID()
	tpl := ruleTemplate(tenant, "mine.yaml", "id: mine\n", scannertemplate.TemplateStatusActive)
	templates := &tenantTemplates{byTenant: map[shared.ID][]*scannertemplate.ScannerTemplate{tenant: {tpl}}}

	cases := []struct {
		set          string
		wantRS       string
		wantTpls     int
		wantFeatures []string
	}{
		{"", "both", 1, nil},
		{"both", "both", 1, nil},
		{"platform", "platform", 0, nil},
		{"tenant", "tenant", 1, []string{scannertemplate.SensorCapabilityRuleSources}},
	}
	for _, c := range cases {
		t.Run("set="+c.set, func(t *testing.T) {
			svc, cmds := ruleSourcesService(templates, nil)
			sc := nucleiScan(tenant, tpl.ID)
			if err := sc.SetRuleSources(c.set); err != nil {
				t.Fatal(err)
			}
			p, err := dispatch(t, svc, cmds, sc)
			if err != nil {
				t.Fatal(err)
			}
			if p.RuleSources != c.wantRS || len(p.CustomTemplates) != c.wantTpls || !slices.Equal(p.RequiredFeatures, c.wantFeatures) {
				t.Fatalf("payload = %+v; want rule_sources %s, %d templates, features %v", p, c.wantRS, c.wantTpls, c.wantFeatures)
			}
			if c.wantTpls == 1 {
				body, _ := base64.StdEncoding.DecodeString(p.CustomTemplates[0].Content)
				if string(body) != "id: mine\n" || p.CustomTemplates[0].ID != tpl.ID.String() {
					t.Fatalf("template = %+v", p.CustomTemplates[0])
				}
			}
		})
	}
}

// The trigger narrows a platform-only scan in memory: the opt-in check and
// the preflight then count no templates; the map the scan was loaded with
// is not changed.
func TestApplyRuleSourcesAtTrigger_PlatformDropsTemplatesInMemoryOnly(t *testing.T) {
	tenant := shared.NewID()
	sc := nucleiScan(tenant, shared.NewID())
	original := sc.ScannerConfig
	sc.RuleSources = scannertemplate.RuleSourcesPlatform
	svc, _ := ruleSourcesService(&tenantTemplates{}, nil)
	rs, err := svc.applyRuleSourcesAtTrigger(context.Background(), sc)
	if err != nil || rs != scannertemplate.RuleSourcesPlatform {
		t.Fatalf("rs = %q, err = %v", rs, err)
	}
	if len(customTemplateIDs(sc.ScannerConfig)) != 0 {
		t.Fatal("platform-only run still names custom templates")
	}
	if len(customTemplateIDs(original)) != 1 {
		t.Fatal("the loaded config was mutated")
	}
}

func TestRuleSources_TenantWithoutTemplatesIsRefused(t *testing.T) {
	tenant := shared.NewID()
	sc := nucleiScan(tenant)
	sc.RuleSources = scannertemplate.RuleSourcesTenant
	if err := checkScanRuleSources(sc); err == nil {
		t.Fatal("create/update accepted tenant-only with no templates")
	}
	svc, cmds := ruleSourcesService(&tenantTemplates{}, nil)
	if _, err := dispatch(t, svc, cmds, sc); err == nil || !strings.Contains(err.Error(), "names no custom template") {
		t.Fatalf("err = %v; want the trigger refused", err)
	}
	sc.RuleSources = scannertemplate.RuleSourcesBoth
	if err := checkScanRuleSources(sc); err != nil {
		t.Fatalf("both without templates refused: %v", err)
	}
}

// Fail closed: when the organization's templates are to run, a template
// that cannot be resolved fails the run instead of being skipped.
func TestRuleSources_UnresolvedTemplatesFailTheRun(t *testing.T) {
	tenant := shared.NewID()
	active := ruleTemplate(tenant, "a.yaml", "id: a\n", scannertemplate.TemplateStatusActive)
	revoked := ruleTemplate(tenant, "r.yaml", "id: r\n", scannertemplate.TemplateStatusRevoked)
	store := &tenantTemplates{byTenant: map[shared.ID][]*scannertemplate.ScannerTemplate{tenant: {active, revoked}}}

	cases := map[string]struct {
		ids   []shared.ID
		err   error
		bogus bool
		want  string
	}{
		"deleted template": {ids: []shared.ID{active.ID, shared.NewID()}, want: "not found"},
		"revoked template": {ids: []shared.ID{active.ID, revoked.ID}, want: "not active (r.yaml)"},
		"store error":      {ids: []shared.ID{active.ID}, err: errors.New("db down"), want: "could not be resolved"},
		"malformed id":     {ids: []shared.ID{active.ID}, bogus: true, want: "not found"},
	}
	for name, c := range cases {
		for _, rs := range []string{"both", "tenant"} {
			t.Run(name+"/"+rs, func(t *testing.T) {
				store.err = c.err
				defer func() { store.err = nil }()
				svc, cmds := ruleSourcesService(store, nil)
				sc := nucleiScan(tenant, c.ids...)
				if c.bogus {
					sc.ScannerConfig["custom_template_ids"] = append(sc.ScannerConfig["custom_template_ids"].([]any), "not-a-uuid")
				}
				sc.RuleSources = scannertemplate.RuleSources(rs)
				_, err := dispatch(t, svc, cmds, sc)
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("err = %v; want the run failed with %q", err, c.want)
				}
			})
		}
	}
	// A platform-only run resolves nothing, so a broken template store does
	// not stop it.
	store.err = errors.New("db down")
	defer func() { store.err = nil }()
	svc, cmds := ruleSourcesService(store, nil)
	sc := nucleiScan(tenant, active.ID)
	sc.RuleSources = scannertemplate.RuleSourcesPlatform
	if p, err := dispatch(t, svc, cmds, sc); err != nil || len(p.CustomTemplates) != 0 {
		t.Fatalf("platform-only run: payload %+v, err %v", p, err)
	}
}

// Tenant isolation: a scan of tenant B that names tenant A's template ids
// never carries them; the run fails as "not found".
func TestRuleSources_AnotherTenantsTemplatesNeverReachTheCommand(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	secret := ruleTemplate(tenantA, "a-internal.yaml", "id: a-internal\n# internal.example.com\n", scannertemplate.TemplateStatusActive)
	store := &tenantTemplates{byTenant: map[shared.ID][]*scannertemplate.ScannerTemplate{tenantA: {secret}}}
	svc, cmds := ruleSourcesService(store, nil)
	sc := nucleiScan(tenantB, secret.ID)
	for _, rs := range []string{"both", "tenant"} {
		sc.RuleSources = scannertemplate.RuleSources(rs)
		if _, err := dispatch(t, svc, cmds, sc); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("%s: err = %v; want tenant A's template not found for tenant B", rs, err)
		}
	}
	for _, c := range cmds.cmds {
		if strings.Contains(string(c.Payload), base64.StdEncoding.EncodeToString(secret.Content)) {
			t.Fatal("tenant A's template content reached a tenant B command")
		}
	}
}

func TestEffectiveRuleSources_ScanThenProfileThenBoth(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	own := &scanprofile.ScanProfile{ID: shared.NewID(), TenantID: tenant, RuleSources: scannertemplate.RuleSourcesTenant}
	foreign := &scanprofile.ScanProfile{ID: shared.NewID(), TenantID: other, RuleSources: scannertemplate.RuleSourcesPlatform}
	profiles := &tenantProfiles{byID: map[shared.ID]*scanprofile.ScanProfile{own.ID: own, foreign.ID: foreign}}
	svc, _ := ruleSourcesService(&tenantTemplates{}, profiles)
	ctx := context.Background()

	sc := nucleiScan(tenant)
	if rs, _ := svc.effectiveRuleSources(ctx, sc); rs != scannertemplate.RuleSourcesBoth {
		t.Fatalf("no setting, no profile = %q, want both", rs)
	}
	sc.ProfileID = &own.ID
	if rs, _ := svc.effectiveRuleSources(ctx, sc); rs != scannertemplate.RuleSourcesTenant {
		t.Fatalf("inherited = %q, want the profile's tenant", rs)
	}
	sc.RuleSources = scannertemplate.RuleSourcesPlatform
	if rs, _ := svc.effectiveRuleSources(ctx, sc); rs != scannertemplate.RuleSourcesPlatform {
		t.Fatalf("scan setting = %q, want it to win", rs)
	}
	// Another tenant's profile id is not readable: it counts as none.
	sc.RuleSources = ""
	sc.ProfileID = &foreign.ID
	if rs, _ := svc.effectiveRuleSources(ctx, sc); rs != scannertemplate.RuleSourcesBoth {
		t.Fatalf("foreign profile = %q, want both (not the other tenant's platform)", rs)
	}
	// A profile read error refuses (fail closed).
	profiles.err = errors.New("db down")
	sc.ProfileID = &own.ID
	if _, err := svc.effectiveRuleSources(ctx, sc); err == nil {
		t.Fatal("a profile read error was ignored")
	}
}

func TestRuleSourcesOfRunIgnoresUnknownValues(t *testing.T) {
	for v, want := range map[any]scannertemplate.RuleSources{
		"tenant": scannertemplate.RuleSourcesTenant, "everything": scannertemplate.RuleSourcesBoth, 7: scannertemplate.RuleSourcesBoth,
	} {
		if got := ruleSourcesOfRun(map[string]any{RunContextKeyRuleSources: v}); got != want {
			t.Errorf("ruleSourcesOfRun(%v) = %q, want %q", v, got, want)
		}
	}
	if got := ruleSourcesOfRun(nil); got != scannertemplate.RuleSourcesBoth {
		t.Errorf("no context = %q", got)
	}
}

func TestWithRequiredFeatureKeepsOthersAndAddsOnce(t *testing.T) {
	got := withRequiredFeature([]any{"net.confined@1"}, scannertemplate.SensorCapabilityRuleSources)
	got = withRequiredFeature(got, scannertemplate.SensorCapabilityRuleSources)
	if !slices.Equal(got, []string{"net.confined@1", scannertemplate.SensorCapabilityRuleSources}) {
		t.Fatalf("features = %v", got)
	}
}
