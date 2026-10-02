package unit

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/outbox"
	"github.com/openctemio/api/pkg/domain/shared"
)

// This guards the "silently inert" defect class as it appears in the
// notification path: an event type that production code enqueues but that no
// integration can ever be configured to receive.
//
// integration_notification_extensions.enabled_event_types is an opt-in
// whitelist. NotificationExtension.ShouldNotifyEventType matches a literal
// member of that list (after legacy aliasing); anything else matches nothing.
// An outbox entry carrying an unregistered event type is therefore enqueued
// successfully, matches zero integrations, takes the "no matching integrations"
// branch in internal/app/outbox.Service, is marked completed, archived and
// deleted. No error, no warning, no delivery — the notification simply never
// happened.
//
// Nothing about that is visible at compile time: EnqueueParams.EventType is a
// plain string, so a typo, a new event type, or a type someone forgot to add to
// AllEventTypes() all look identical to the compiler. This test closes that gap
// by reading the source.

// outboxParamStructs are the struct types whose EventType field becomes an
// outbox entry's routing key. Matching is on the type's final identifier, so an
// aliased import (outboxapp "…/internal/app/outbox") is still recognized.
//
// Matching by type — rather than grepping for `EventType:` — is load-bearing.
// The codebase has at least three unrelated structs with an EventType field:
// ioc.TelemetryEvent (EDR telemetry, e.g. "network_connect"),
// notifier.WebhookPayload (the outgoing webhook envelope, e.g. "notification")
// and scope.scopeChangeEvent (a WebSocket payload). None of them routes through
// the whitelist, and demanding that their values be registered notification
// event types would be wrong.
var outboxParamStructs = map[string]bool{
	"EnqueueParams": true, // internal/app/outbox.EnqueueParams
	"OutboxParams":  true, // pkg/domain/outbox.OutboxParams
}

// emittedEventType is one string literal assigned to an outbox EventType field.
type emittedEventType struct {
	value string
	pos   string // file:line, relative to the repo root
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate go.mod above the test working directory")
	return ""
}

// scanEmittedOutboxEventTypes parses every non-test Go file in the module and
// returns the string literals assigned to the EventType field of an outbox
// param struct.
//
// It reads the AST rather than the raw bytes on purpose: a commented-out
// emission is not an emission. internal/app/finding/vulnerability_service.go
// carries a TODO mentioning EventType: "finding_status_changed" that nothing
// executes, and a text search would demand it be registered — adding a UI
// checkbox that could never fire, which is this bug's mirror image.
//
// Non-literal values (EventType: params.EventType) are counted and returned
// separately: they are pass-throughs whose real value is set at a call site
// this scan already covers, so they cannot be checked here and are not failures.
func scanEmittedOutboxEventTypes(t *testing.T, root string) (found []emittedEventType, filesParsed, litsFound, dynamic int) {
	t.Helper()

	skipDirs := map[string]bool{
		".git": true, "vendor": true, "node_modules": true, "docs": true,
	}

	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		filesParsed++

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || lit.Type == nil {
				return true
			}
			var typeName string
			switch tt := lit.Type.(type) {
			case *ast.Ident:
				typeName = tt.Name
			case *ast.SelectorExpr:
				typeName = tt.Sel.Name
			}
			if !outboxParamStructs[typeName] {
				return true
			}
			litsFound++

			for _, elt := range lit.Elts {
				kv, isKV := elt.(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				key, isIdent := kv.Key.(*ast.Ident)
				if !isIdent || key.Name != "EventType" {
					continue
				}
				basic, isBasic := kv.Value.(*ast.BasicLit)
				if !isBasic || basic.Kind != token.STRING {
					dynamic++
					continue
				}
				value, unqErr := strconv.Unquote(basic.Value)
				if unqErr != nil {
					continue
				}
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				found = append(found, emittedEventType{
					value: value,
					pos:   rel + ":" + strconv.Itoa(fset.Position(basic.Pos()).Line),
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found, filesParsed, litsFound, dynamic
}

func TestEmittedOutboxEventTypes_AreRegistered(t *testing.T) {
	root := repoRoot(t)
	emitted, filesParsed, litsFound, dynamic := scanEmittedOutboxEventTypes(t, root)

	// Without these the test passes by finding nothing — the same silent
	// no-op it exists to catch. If the outbox param structs are renamed or
	// moved, this fails loudly instead of going quiet.
	if filesParsed == 0 {
		t.Fatal("parsed no Go sources; the guard is not guarding anything")
	}
	if litsFound == 0 {
		t.Fatalf("found no composite literals of %v in %d files; "+
			"the outbox param structs were probably renamed — update outboxParamStructs",
			sortedKeys(outboxParamStructs), filesParsed)
	}
	if len(emitted) == 0 {
		t.Fatalf("found %d outbox param literals but no literal EventType values; "+
			"the guard is not guarding anything", litsFound)
	}
	t.Logf("scanned %d files: %d outbox param literals, %d literal event types, %d pass-through values",
		filesParsed, litsFound, len(emitted), dynamic)

	registered := make(map[integration.EventType]bool)
	for _, info := range integration.AllEventTypes() {
		registered[info.Type] = true
	}

	// Report each offending type once, listing every site that emits it.
	sites := make(map[string][]string)
	order := make([]string, 0)
	for _, e := range emitted {
		// MapLegacyEventType so the four legacy aggregates ("findings",
		// "exposures", "scans", "alerts") still count as registered.
		if registered[integration.MapLegacyEventType(integration.EventType(e.value))] {
			continue
		}
		if _, seen := sites[e.value]; !seen {
			order = append(order, e.value)
		}
		sites[e.value] = append(sites[e.value], e.pos)
	}
	sort.Strings(order)

	for _, value := range order {
		t.Errorf("outbox event type %q is emitted but not registered in integration.AllEventTypes()\n"+
			"  emitted at: %s\n"+
			"  enabled_event_types is an opt-in whitelist, so this event matches zero integrations,\n"+
			"  takes the \"no matching integrations\" branch and is marked completed and deleted —\n"+
			"  delivered nowhere, with no error and no warning.\n"+
			"  Fix: add a constant and an AllEventTypes() entry in\n"+
			"  pkg/domain/integration/notification_extension.go, decide whether it belongs in\n"+
			"  DefaultEnabledEventTypes(), and add a migration appending it to existing\n"+
			"  non-empty enabled_event_types arrays (see migrations/000202).",
			value, strings.Join(sites[value], ", "))
	}
}

// TestDefaultEnabledEventTypes_AreRegistered catches the other half of the same
// mistake: a default that is not a real event type is silently never matched,
// because ShouldNotifyEventType compares literal values.
func TestDefaultEnabledEventTypes_AreRegistered(t *testing.T) {
	defaults := integration.DefaultEnabledEventTypes()
	if len(defaults) == 0 {
		t.Fatal("DefaultEnabledEventTypes() is empty; the guard is not guarding anything")
	}

	registered := make(map[integration.EventType]bool)
	for _, info := range integration.AllEventTypes() {
		registered[info.Type] = true
	}
	for _, et := range defaults {
		if !registered[integration.MapLegacyEventType(et)] {
			t.Errorf("DefaultEnabledEventTypes() contains %q, which is not in AllEventTypes(); "+
				"it would be written into every new integration's whitelist and never match anything", et)
		}
	}
}

// TestDefaultWhitelist_DeliversSLABreach is the user-visible claim of this
// change, exercised through the real matching path rather than by asserting a
// constant exists: an integration created with the shipped defaults must
// actually match an sla_breach entry in Service.shouldSendToIntegration.
//
// The observable is the archived event's IntegrationsMatched. Before this
// change it was 0 and the entry was archived as skipped.
func TestDefaultWhitelist_DeliversSLABreach(t *testing.T) {
	tests := []struct {
		name        string
		eventType   string
		severity    string
		wantMatched int
	}{
		{
			name:        "sla_breach reaches a default integration",
			eventType:   "sla_breach",
			severity:    "high", // what BreachOutboxAdapter actually enqueues
			wantMatched: 1,
		},
		{
			name:        "finding_assigned reaches a default integration",
			eventType:   "finding_assigned",
			severity:    "critical",
			wantMatched: 1,
		},
		{
			name:        "workflow_notification reaches a default integration",
			eventType:   "workflow_notification",
			severity:    "high",
			wantMatched: 1,
		},
		{
			name:        "approval_requested reaches a default integration",
			eventType:   "approval_requested",
			severity:    "high",
			wantMatched: 1,
		},
		{
			// Negative control. Without this the test would still pass if
			// ShouldNotifyEventType were changed to match everything, which
			// would be a different and worse bug.
			name:        "an unregistered event type still matches nothing",
			eventType:   "totally_made_up_event",
			severity:    "critical",
			wantMatched: 0,
		},
		{
			// approval_approved is registered but deliberately NOT default-on.
			name:        "a registered but non-default type is not delivered by default",
			eventType:   "approval_approved",
			severity:    "critical",
			wantMatched: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID := shared.NewID()
			// Retries deliberately exhausted. The decrypt stub below fails, so a
			// MATCHED integration produces an all-failed result; with retries
			// left that reschedules the entry and it is never archived, leaving
			// nothing to assert on. Exhausted, the all-failed result is terminal
			// and both outcomes reach the archive, so IntegrationsMatched is a
			// like-for-like comparison across the cases.
			entry := makeTestOutboxEntryExhausted(tenantID, tt.eventType, tt.severity)

			// NewNotificationExtension is what the create path uses, so this is
			// exactly the whitelist a newly created integration receives.
			ext := integration.NewNotificationExtension(shared.NewID())
			connected := makeConnectedIntegration(tenantID, integration.ProviderSlack, ext)

			outboxRepo := &mockOutboxRepo{fetchPendingResult: []*outbox.Outbox{entry}}
			eventRepo := &mockEventRepo{}
			notifRepo := &mockNotifExtRepoForService{
				listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
			}
			svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

			if _, _, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50); err != nil {
				t.Fatalf("ProcessOutboxBatch: %v", err)
			}

			if eventRepo.lastCreated == nil {
				t.Fatal("no event was archived; nothing was processed")
			}
			if got := eventRepo.lastCreated.IntegrationsMatched(); got != tt.wantMatched {
				t.Errorf("IntegrationsMatched = %d, want %d for event type %q with defaults %v",
					got, tt.wantMatched, tt.eventType, integration.DefaultEnabledEventTypes())
			}
		})
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
