package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	moduledom "github.com/openctemio/openctem/server/pkg/domain/module"
)

// jobInfrastructure are controller constructors that are not jobs of a
// module: the runner itself and generic building blocks.
var jobInfrastructure = map[string]string{
	"Manager":                "the controller runner",
	"PrometheusMetrics":      "controller metrics",
	"PurgeController":        "generic table purge, configured per retention policy",
	"ControlChangePublisher": "publishes control changes for other jobs; schedules nothing",
	"VersionCheckController": "instance-level release feed check for the platform console; no organization module (RFC-105)",
	"DurableJobsController":  "runner of durable jobs queued by other features (ticket status sync, invitation e-mail); schedules nothing itself",
}

// jobSkipProof names, for every job owned by a module that can be switched off,
// the test that proves the job leaves a tenant with that module off alone.
// A job that must keep running whatever the tenant chose (retention, repairs
// that keep the scope boundary consistent, platform-wide feeds) is owned by a
// core module instead, and needs no entry.
var jobSkipProof = map[string]struct{ dir, test string }{
	"AIAgentSweepController":          {"internal/app/aianalysis", "TestSweep_SkipsTenantWithAITriageOff"},
	"CertMonitorController":           {"internal/infra/controller", "TestCertMonitor_SkipsTenantWithAttackSurfaceOff"},
	"EASMDNSController":               {"internal/infra/controller", "TestEASMDNSController_Reconcile"},
	"EASMLookalikeController":         {"internal/infra/controller", "TestEASMLookalike_SkipsTenantWithAttackSurfaceOff"},
	"PageMonitorController":           {"internal/infra/controller", "TestPageMonitor_SkipsTenantWithAttackSurfaceOff"},
	"EASMNetworkSeedController":       {"internal/infra/controller", "TestEASMNetworkSeed_SkipsTenantWithAttackSurfaceOff"},
	"EASMAddressAutoAddController":    {"internal/infra/controller", "TestEASMAddressAutoAdd_SkipsTenantWithAttackSurfaceOff"},
	"EASMPostureController":           {"internal/app/posture", "TestRefreshDue_SkipsTenantWithAttackSurfaceOff"},
	"EASMWeeklyDigestController":      {"internal/infra/controller", "TestEASMWeeklyDigest_SkipsTenantWithAttackSurfaceOff"},
	"GraphEnrichmentController":       {"internal/infra/controller", "TestGraphEnrichment_SkipsTenantWithModuleDisabled"},
	"ScopeJoinController":             {"internal/app/easm", "TestScopeJoinReevaluateAll_SkipsAttackSurfaceOff"},
	"ControlTestSchedulerController":  {"internal/infra/controller", "TestControlTestScheduler_SkipsUnsubscribedTenant"},
	"RemediationProgressController":   {"internal/app/exposure", "TestCampaignProgress_SkipsTenantWithRemediationOff"},
	"RemediationTaskController":       {"internal/app/remediation", "TestTaskReconcile_SkipsTenantWithRemediationOff_AndDoesNotStarveOthers"},
	"RemediationTaskQueryController":  {"internal/app/remediation", "TestTaskAutoInclude_SkipsTenantWithRemediationOff_AndDoesNotStarveOthers"},
	"TaskTicketController":            {"internal/infra/controller", "TestTaskTicket_SkipsTenantWithRemediationOff"},
	"RemediationSuggestionController": {"internal/app/remediation", "TestSuggestionsRunAll_SkipsTenantWithRemediationOff"},
	"ReportScheduler":                 {"internal/infra/controller", "TestReportScheduler_SkipsUnsubscribedTenant"},
	"ProgramAssignmentController":     {"internal/infra/controller", "TestProgramAssignment_SkipsTenantWithScopeOff"},
	"ProgramFeedController":           {"internal/app/programfeed", "TestReconcile_SkipsTenantWithScopeOff"},
	"ProgramSyncController":           {"internal/app/bountyprogram", "TestSyncDue_SkipsTenantWithScopeOff"},
	"ContentSourceSyncController":     {"internal/app/contentsource", "TestRuleSources_ModuleOffSkipsSync_DB"},
	"ThreatAlertPlannerController":    {"internal/app/threatalert", "TestPolicy_InactiveWhenThreatIntelOff"},
	"ThreatModelRefreshController":    {"internal/infra/controller", "TestThreatModelRefresh_SkipsTenantWithModuleDisabled"},
}

// Every job of a module that can be switched off is proven to skip a tenant
// that has it off: the registry lists the job under its module, and the
// table above names a test that exists, lives in the package of the job, and
// uses that module.
func TestEveryModuleJobSkipsADisabledTenant(t *testing.T) {
	root := repoRoot(t)
	gen, err := os.ReadFile(filepath.Join(root, "pkg", "domain", "module", "registry_generated.go"))
	if err != nil {
		t.Fatal(err)
	}
	constOf := func(id string) string {
		m := regexp.MustCompile(`(Module\w+)\s*=\s*"` + regexp.QuoteMeta(id) + `"`).FindSubmatch(gen)
		if m == nil {
			t.Fatalf("no constant for module %s", id)
		}
		return string(m[1])
	}
	testSource := func(dir, name string) (string, bool) {
		files, _ := filepath.Glob(filepath.Join(root, dir, "*_test.go"))
		fset := token.NewFileSet()
		for _, f := range files {
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range af.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
					b, _ := os.ReadFile(f)
					return string(b), true
				}
			}
		}
		return "", false
	}

	owned := map[string]string{}
	for _, d := range moduledom.Registry {
		if d.Core {
			continue
		}
		for _, j := range d.Jobs {
			owned[j] = d.ID
		}
	}
	var problems []string
	for job, module := range owned {
		proof, ok := jobSkipProof[job]
		if !ok {
			problems = append(problems, job+" (module "+module+"): add a test that it skips a tenant with the module off to jobSkipProof, or move the job to a core module if it must always run")
			continue
		}
		src, found := testSource(proof.dir, proof.test)
		if !found {
			problems = append(problems, job+": test "+proof.test+" not found in "+proof.dir)
			continue
		}
		if !strings.Contains(src, constOf(module)) && !strings.Contains(src, `"`+module+`"`) {
			problems = append(problems, job+": "+proof.test+" does not use module "+module)
		}
	}
	for job := range jobSkipProof {
		if _, ok := owned[job]; !ok {
			problems = append(problems, job+" has a proof entry but is not owned by a module that can be switched off")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("module jobs without proof:\n  %s", strings.Join(problems, "\n  "))
	}
}

// Every background controller the server builds is owned by exactly one
// module of the registry (configs/modules/<id>.yaml, `jobs`), so a job of a
// module that can be switched off is a decision, not an accident (RFC-064 R2).
func TestEveryJobBelongsToAModule(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "server")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	built := map[string]string{}
	fset := token.NewFileSet()
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, ent.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "New") {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "controller" {
				built[strings.TrimPrefix(sel.Sel.Name, "New")] = ent.Name() + ":" + itoa(fset.Position(ce.Pos()).Line)
			}
			return true
		})
	}
	if len(built) < 30 {
		t.Fatalf("found only %d controllers: the reader is broken, not the code", len(built))
	}

	owner := map[string]string{}
	for _, d := range moduledom.Registry {
		for _, j := range d.Jobs {
			owner[j] = d.ID
		}
	}
	var problems []string
	for name, pos := range built {
		if _, ok := jobInfrastructure[name]; ok {
			continue
		}
		if _, ok := owner[name]; !ok {
			problems = append(problems, name+" ("+pos+"): add it to the `jobs` of its module in configs/modules/<id>.yaml")
		}
	}
	for name, id := range owner {
		if _, ok := built[name]; !ok {
			problems = append(problems, id+" lists job "+name+", which the server does not build")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("background jobs and the module registry disagree:\n  %s", strings.Join(problems, "\n  "))
	}
}
