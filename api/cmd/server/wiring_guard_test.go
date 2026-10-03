package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
)

// This guards a defect class this codebase keeps producing: code that runs but
// can never have an effect.
//
// PriorityClassificationService exposes optional collaborators through Set*
// seams and nil-guards every one of them, so forgetting to call a setter in the
// composition root produces no build error, no vet warning, no panic and no log
// line — the feature simply never happens. That is exactly how
// SetChangePublisher stayed unwired: the service emitted a PriorityChangeEvent
// on every class transition, publishIfChanged returned early on the nil
// publisher, and the PriorityFloodGuard that was wired sat guarding a fan-out
// that could not occur. A finding escalating from P3 to P0 notified nobody.
//
// The test resolves the Set* seams by reflection rather than a hand-written
// list, so a NEW optional collaborator added later is caught too: it must
// either be wired in cmd/server or be given an explicit, documented entry in
// optionalPrioritySeams below. "I forgot" is not a passing state.

// optionalPrioritySeams lists Set* seams on PriorityClassificationService that
// are deliberately NOT wired in cmd/server, each with the reason. Empty today:
// every seam is wired. Adding an entry is a conscious decision that shows up in
// review.
var optionalPrioritySeams = map[string]string{}

// prioritySeamsWiredInCmdServer parses this package's non-test sources and
// returns the set of method names invoked on the Services.PriorityClassification
// field.
//
// It matches on the selector expression rather than the bare method name on
// purpose: cmd/server/handlers.go also calls a method named SetChangePublisher,
// on the unrelated CompensatingControlHandler. A bare name search would match
// that and pass while the priority publisher stayed nil.
//
// Limitation: a call made through a local alias (pc := s.PriorityClassification;
// pc.SetX(...)) is not recognized and would fail this test. That is the safe
// direction to be wrong in, and the fix is to call it on the field.
func prioritySeamsWiredInCmdServer(t *testing.T) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/server: %v", err)
	}

	fset := token.NewFileSet()
	wired := make(map[string]bool)
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			var buf bytes.Buffer
			if err := printer.Fprint(&buf, fset, sel.X); err != nil {
				return true
			}
			if strings.HasSuffix(buf.String(), ".PriorityClassification") {
				wired[sel.Sel.Name] = true
			}
			return true
		})
	}
	// Without this the test passes vacuously if the sources ever move.
	if parsed == 0 {
		t.Fatal("parsed no cmd/server sources; the guard is not guarding anything")
	}
	return wired
}

// selectorCall is one method-call selector found in the sources: the printed
// receiver expression (e.g. "services.Email", "s.AITriage") and the method name.
type selectorCall struct {
	recv   string
	method string
}

// allSelectorCallsInCmdServer parses this package's non-test sources and returns
// every method-call selector, so callers can assert that a specific
// receiver-field.method pair is present. Same AST approach (and same local-alias
// limitation) as prioritySeamsWiredInCmdServer.
func allSelectorCallsInCmdServer(t *testing.T) []selectorCall {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/server: %v", err)
	}

	fset := token.NewFileSet()
	var calls []selectorCall
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			var buf bytes.Buffer
			if err := printer.Fprint(&buf, fset, sel.X); err != nil {
				return true
			}
			calls = append(calls, selectorCall{recv: buf.String(), method: sel.Sel.Name})
			return true
		})
	}
	if parsed == 0 {
		t.Fatal("parsed no cmd/server sources; the guard is not guarding anything")
	}
	return calls
}

// guardedInertSeams are Set* collaborators that were built but never injected at
// the composition root, so the feature they feed silently never ran. Each was
// fixed; this list keeps them from regressing. The field is the trailing
// selector on the Services value (works for both `s.X` and `services.X`).
var guardedInertSeams = []struct {
	field   string // e.g. ".Email"
	setter  string
	feature string
}{
	{".Email", "SetTenantSMTPResolver", "per-tenant SMTP"},
	{".AITriage", "SetWorkflowDispatcher", "AI-triage workflow events"},
	{".Pentest", "SetTenantMemberChecker", "pentest cross-tenant member check"},
	{".Tenant", "SetMemberStatusEmailNotifier", "member suspend/reactivate emails"},
	{".Module", "SetWSBroadcaster", "module.updated WebSocket push on module toggle"},
	{".SCIMProvisioning", "SetDomainVerifier", "SCIM attaches existing accounts only on a verified domain"},
}

// TestInertWiringSeams_StayWired asserts each previously-dead Set* seam is
// invoked on its Services field in cmd/server. Because these are nil-guarded,
// dropping the wire produces no build or vet error — only this test catches it.
func TestInertWiringSeams_StayWired(t *testing.T) {
	calls := allSelectorCallsInCmdServer(t)
	for _, seam := range guardedInertSeams {
		found := false
		for _, c := range calls {
			if c.method == seam.setter && strings.HasSuffix(c.recv, seam.field) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Services%s.%s (%s) is never called in cmd/server.\n"+
				"The service nil-guards this collaborator, so leaving it unwired silently disables the feature.\n"+
				"Re-wire it in cmd/server (services.go or main.go).", seam.field, seam.setter, seam.feature)
		}
	}
}

func TestPriorityClassificationSeams_AreWiredOrExplicitlyOptional(t *testing.T) {
	seams := make([]string, 0, 8)
	typ := reflect.TypeOf(&app.PriorityClassificationService{})
	for i := 0; i < typ.NumMethod(); i++ {
		if name := typ.Method(i).Name; strings.HasPrefix(name, "Set") {
			seams = append(seams, name)
		}
	}
	// Without this the test passes vacuously if the service is ever renamed or
	// its setters restructured — the same silent-no-op failure it exists to
	// catch.
	if len(seams) == 0 {
		t.Fatal("reflection found no Set* seams on PriorityClassificationService; the guard is not guarding anything")
	}

	wired := prioritySeamsWiredInCmdServer(t)

	for _, seam := range seams {
		if reason, exempt := optionalPrioritySeams[seam]; exempt {
			t.Logf("%s intentionally unwired: %s", seam, reason)
			continue
		}
		if !wired[seam] {
			t.Errorf("PriorityClassificationService.%s is never called on Services.PriorityClassification in cmd/server.\n"+
				"The service nil-guards this collaborator, so leaving it unwired silently disables the feature it feeds.\n"+
				"Either wire it in cmd/server/services.go or add it to optionalPrioritySeams with a reason.", seam)
		}
	}
}

// servicesReceiver matches the expressions cmd/server uses for the Services
// value: `s` inside its methods, `services` in main.go, `svc` in the handler
// and worker builders.
var servicesReceiver = regexp.MustCompile(`^(s|services|svc)\.([A-Z]\w*)$`)

// cmdServerServicesUsage parses cmd/server's non-test sources and returns, per
// Services field, every place it is assigned and the set of methods called on it.
func cmdServerServicesUsage(t *testing.T) (assigned map[string][]string, called map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/server: %v", err)
	}
	fset := token.NewFileSet()
	assigned = map[string][]string{}
	called = map[string]bool{}
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					var b bytes.Buffer
					if printer.Fprint(&b, fset, lhs) == nil {
						if m := servicesReceiver.FindStringSubmatch(b.String()); m != nil {
							assigned[m[2]] = append(assigned[m[2]], fset.Position(v.Pos()).String())
						}
					}
				}
			case *ast.SelectorExpr:
				var b bytes.Buffer
				if printer.Fprint(&b, fset, v.X) == nil {
					if m := servicesReceiver.FindStringSubmatch(b.String()); m != nil {
						called[m[2]+"."+v.Sel.Name] = true
					}
				}
			}
			return true
		})
	}
	if parsed == 0 {
		t.Fatal("parsed no cmd/server sources; the guard is not guarding anything")
	}
	return assigned, called
}

// TestServices_EachServiceConstructedOnce guards the split-brain composition
// root. main.go used to replace services.Tenant with a second
// app.NewTenantService; every Set* applied to the first instance was silently
// lost (six features, including GET /settings/data-scope returning 500), and
// adapters that had captured the first instance kept using it. A Services
// field must be assigned in exactly one place. Add a missing collaborator with
// a setter on the existing instance instead of constructing another one.
func TestServices_EachServiceConstructedOnce(t *testing.T) {
	assigned, _ := cmdServerServicesUsage(t)
	if len(assigned) == 0 {
		t.Fatal("found no Services field assignments; the guard is not guarding anything")
	}
	for field, sites := range assigned {
		if len(sites) > 1 {
			t.Errorf("Services.%s is constructed %d times (%s). The later construction discards every "+
				"setter applied to the earlier one; wire the extra collaborator with a setter instead.",
				field, len(sites), strings.Join(sites, ", "))
		}
	}
}

// optionalServiceSetters are Set* methods on Services fields that are
// deliberately NOT called in cmd/server, each with the reason. Everything else
// must be wired: the services nil-guard their collaborators, so an unwired
// setter is a feature that silently never runs.
var optionalServiceSetters = map[string]string{
	// Business operations named Set*, not collaborator seams.
	"Branch.SetDefaultBranch":           "request operation, called by the branch handler",
	"PermVersion.Set":                   "cache operation, not a seam",
	"Role.SetUserRoles":                 "request operation, called by the role handler",
	"SCIMGroups.SetRoleMappings":        "request operation, called by the SCIM token handler",
	"SCIMProvisioning.SetActive":        "SCIM PATCH operation, not a seam",
	"ScanProfile.SetDefaultScanProfile": "request operation, called by the scan profile handler",
	"ThreatIntel.SetSyncEnabled":        "request operation, called by the threat-intel handler",
	"UserDashboard.SetDefault":          "request operation, called by the dashboard handler",
	"Vulnerability.SetFindingTags":      "request operation, called by the finding handler",
	// Real seams left at their defaults on purpose.
	"ScannerTemplate.SetQuota":         "default quota applies; the override exists for tests and future config",
	"Retest.SetClock":                  "test clock; production uses time.Now",
	"Vulnerability.SetFindingNotifier": "deprecated; superseded by the notification outbox",
	"WebSocketHub.SetAuthorizeFunc":    "superseded by SetChannelAccessChecker",
	"WebSocketHub.SetPublisher":        "set by websocket.NewRedisBridge on the hub it is given",
}

// TestServices_EverySetterWiredOrExplicitlyOptional reflects over every
// Services field and requires each of its Set* methods to be called on that
// field somewhere in cmd/server, or to be listed in optionalServiceSetters with
// a reason. This generalizes the per-service guards above: a collaborator added
// later, on any service, cannot ship unwired.
func TestServices_EverySetterWiredOrExplicitlyOptional(t *testing.T) {
	_, called := cmdServerServicesUsage(t)
	typ := reflect.TypeOf(Services{})
	checked := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.Ptr {
			continue
		}
		for j := 0; j < f.Type.NumMethod(); j++ {
			m := f.Type.Method(j).Name
			if !strings.HasPrefix(m, "Set") {
				continue
			}
			checked++
			key := f.Name + "." + m
			if _, ok := optionalServiceSetters[key]; ok {
				continue
			}
			if !called[key] {
				t.Errorf("Services.%s is never called in cmd/server. The service nil-guards this collaborator, "+
					"so leaving it unwired silently disables the feature. Wire it, or add it to "+
					"optionalServiceSetters with a reason.", key)
			}
		}
	}
	if checked == 0 {
		t.Fatal("reflection found no Set* methods on Services fields; the guard is not guarding anything")
	}
	for key := range optionalServiceSetters {
		if called[key] {
			t.Errorf("%s is listed as optional but is wired; remove it from optionalServiceSetters", key)
		}
	}
}
