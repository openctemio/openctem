package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
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
