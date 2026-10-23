package handler

// Publish, rollback, switching on and manual runs check the permissions of
// the steps that actually run (RFC-125 §5), against real Postgres:
//   - a live automation runs its published version, so a caller lacking a
//     permission only that version needs is refused when switching it on or
//     starting a manual run, even if the draft needs none;
//   - publish checks the exact definition it stores;
//   - publishing is one transaction and rollback validates the graph.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *wfDB) versionCount(wf string) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRowContext(f.ctx, `SELECT count(*) FROM automation_versions WHERE automation_id = $1`, wf).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestWorkflowVersionAuthz_DB(t *testing.T) {
	f := newWFDB(t)
	allow := func(automationdom.Definition) error { return nil }
	in := func(wf string, authorize func(automationdom.Definition) error) automationsvc.PublishInput {
		return automationsvc.PublishInput{
			TenantID: shared.MustIDFromString(f.tenantA), UserID: shared.MustIDFromString(f.admin),
			WorkflowID: shared.MustIDFromString(wf), Authorize: authorize,
		}
	}

	t.Run("switching on and manual runs check the published version", func(t *testing.T) {
		nodes, edges := tagFlow("p") // add_tags needs findings:write, which the editor lacks
		wf := f.create(nodes, edges)
		p := map[string]string{"id": wf}
		if s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, p)); s != http.StatusOK {
			t.Fatalf("publish = %d %s", s, b)
		}
		// The draft now needs no permission: a manual trigger alone.
		n2 := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"manual"}}]`
		if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+n2+`,"edges":[]}`, p)); s != http.StatusOK {
			t.Fatalf("edit draft = %d %s", s, b)
		}
		// Switching it on needs the published version's permissions.
		if s, b := f.call(f.h.UpdateWorkflow, f.as(f.editor, http.MethodPut, `{"is_active":true}`, p)); s != http.StatusForbidden {
			t.Fatalf("editor switching on a live automation = %d %s, want 403", s, b)
		}
		if s, b := f.call(f.h.UpdateWorkflow, f.as(f.operator, http.MethodPut, `{"is_active":true}`, p)); s != http.StatusOK {
			t.Fatalf("operator switching on = %d %s, want 200", s, b)
		}
		// A manual run executes the published version: the editor is refused.
		_, err := f.svc.TriggerManualRun(f.ctx, automationsvc.ManualRunInput{
			TenantID: shared.MustIDFromString(f.tenantA), UserID: shared.MustIDFromString(f.editor), WorkflowID: shared.MustIDFromString(wf),
		})
		if !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("editor manual run of a live automation = %v, want forbidden", err)
		}
	})

	t.Run("publish checks the definition it stores", func(t *testing.T) {
		nodes, edges := tagFlow("s")
		wf := f.create(nodes, edges)
		p := map[string]string{"id": wf}
		// Through the handler: the editor lacks findings:write.
		if s, _ := f.call(f.h.Publish, f.as(f.editor, http.MethodPost, `{}`, p)); s != http.StatusForbidden {
			t.Fatalf("editor publish = %d, want 403", s)
		}
		if n := f.versionCount(wf); n != 0 {
			t.Fatalf("a refused publish stored %d versions", n)
		}
		// No check supplied: refused.
		if _, err := f.svc.Publish(f.ctx, in(wf, nil)); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("publish without a permission check = %v, want forbidden", err)
		}
		// A concurrent edit lands while the check runs: the version stores
		// the definition that was checked.
		var checked string
		n2, e2 := tagFlow("late")
		_, err := f.svc.Publish(f.ctx, in(wf, func(d automationdom.Definition) error {
			checked = d.Digest()
			if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+n2+`,"edges":`+e2+`}`, p)); s != http.StatusOK {
				t.Fatalf("concurrent edit = %d %s", s, b)
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		list, err := f.svc.ListVersions(f.ctx, shared.MustIDFromString(f.tenantA), shared.MustIDFromString(wf))
		if err != nil || len(list) != 1 {
			t.Fatalf("versions = %v (%v)", list, err)
		}
		if list[0].Digest != checked || list[0].Definition.Digest() != checked {
			t.Fatalf("stored digest %s, checked %s: the stored definition is not the checked one", list[0].Digest, checked)
		}
	})

	t.Run("publish is one transaction", func(t *testing.T) {
		nodes, edges := tagFlow("tx")
		wf := f.create(nodes, edges)
		w, err := f.svc.GetWorkflow(f.ctx, shared.MustIDFromString(f.tenantA), shared.MustIDFromString(wf))
		if err != nil {
			t.Fatal(err)
		}
		// A version that cannot be published (not pending) fails inside the
		// publish step; the insert must roll back with it.
		v, err := automationdom.NewVersion(w, shared.MustIDFromString(f.admin), automationdom.VersionRetired)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.versions.CreateAndPublish(f.ctx, v, nil, time.Now()); !errors.Is(err, automationdom.ErrVersionNotPending) {
			t.Fatalf("CreateAndPublish of a retired version = %v, want ErrVersionNotPending", err)
		}
		if n := f.versionCount(wf); n != 0 {
			t.Fatalf("failed publish left %d version rows", n)
		}
		var mode string
		_ = f.raw.QueryRowContext(f.ctx, `SELECT mode FROM automations WHERE id = $1`, wf).Scan(&mode)
		if mode != "simulate" {
			t.Fatalf("failed publish left the automation in %s", mode)
		}
	})

	t.Run("rollback validates the target graph", func(t *testing.T) {
		nodes, edges := tagFlow("rb")
		wf := f.create(nodes, edges)
		ctx := context.Background()
		w, err := f.svc.GetWorkflow(ctx, shared.MustIDFromString(f.tenantA), shared.MustIDFromString(wf))
		if err != nil {
			t.Fatal(err)
		}
		// A stored version whose steps are not all reachable from a trigger.
		bad := automationdom.DefinitionOf(w)
		bad.Nodes = append(bad.Nodes, automationdom.DefinitionNode{
			ID: shared.NewID().String(), NodeKey: "orphan", NodeType: automationdom.NodeTypeAction, Name: "orphan", Config: bad.Nodes[0].Config,
		})
		v, err := automationdom.NewVersion(w, shared.MustIDFromString(f.admin), automationdom.VersionSuperseded)
		if err != nil {
			t.Fatal(err)
		}
		v.Definition = bad
		v.Digest = bad.Digest()
		if err := f.versions.Create(ctx, v); err != nil {
			t.Fatal(err)
		}
		before := f.versionCount(wf)
		if _, err := f.svc.Rollback(ctx, in(wf, allow), v.ID); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("rollback to an invalid graph = %v, want a validation error", err)
		}
		if n := f.versionCount(wf); n != before {
			t.Fatalf("refused rollback stored a version (%d -> %d)", before, n)
		}
	})
}
