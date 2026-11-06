package integration

// Accepting a suggestion as the asset owner, without remediation write
// access (docs/rfcs/RFC-098-remediation-tasks.md §6, owner decision D10), on
// a migrated database: only a join into their task or a task route to them,
// only as it is, only when they (or a group they belong to) are the proposed
// owner and own the asset of every finding; never another tenant's.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRemediationOwnerAccept(t *testing.T) {
	r := newAcceptRig(t)
	admin := r.adminCtx()
	member := r.memberCtx()
	// The restricted member is the primary owner of assetA.
	r.exec(`DELETE FROM asset_owners WHERE asset_id = $1`, r.assetA.String())
	r.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`,
		r.assetA.String(), r.member.String())
	// The member's view of assetA comes from an explicit grant, so it stays
	// when the ownership is demoted below (ownership alone would take the
	// view with it).
	r.exec(`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id) VALUES ($1, $2, $3)`,
		r.tenant.String(), r.assetA.String(), r.member.String())
	asOwner := func(sg *remediation.Suggestion, edit func(*remediationapp.AcceptInput)) (*remediation.AcceptResult, error) {
		in := remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.member, AsOwner: true}
		if edit != nil {
			edit(&in)
		}
		return r.sug.Accept(member, in, auditapp.AuditContext{})
	}
	only := func(kind remediation.SuggestionKind) *remediation.Suggestion {
		t.Helper()
		for _, s := range r.list(admin) {
			if s.Kind == kind {
				return s
			}
		}
		t.Fatalf("no %s suggestion", kind)
		return nil
	}

	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P1")
	r.run()
	newGroup := only(remediation.SuggestionNewGroup)
	require.Len(t, newGroup.Partitions, 1)
	assert.Equal(t, r.member.String(), newGroup.Partitions[0].OwnerUser)
	// Starting a new fix needs write access, even for the owner.
	_, err := asOwner(newGroup, nil)
	assert.ErrorIs(t, err, remediationapp.ErrOwnerAcceptKind)
	assert.ErrorIs(t, err, shared.ErrForbidden)

	res, err := r.sug.Accept(admin, remediationapp.AcceptInput{TenantID: r.tenant, ID: newGroup.ID, Version: newGroup.Version, ActorID: &r.admin},
		auditapp.AuditContext{})
	require.NoError(t, err)
	require.Len(t, res.TaskIDs, 1)
	task := res.TaskIDs[0]

	// A new finding on the member's asset: a join into the member's task.
	late := r.keyed(r.assetA, djangoKey, "P2")
	r.run()
	join := only(remediation.SuggestionJoin)

	// As it is only: no edits, no removed findings, no auto-join.
	for name, edit := range map[string]func(*remediationapp.AcceptInput){
		"title":     func(in *remediationapp.AcceptInput) { s := "Mine"; in.Title = &s },
		"exclude":   func(in *remediationapp.AcceptInput) { in.Exclude = []shared.ID{late} },
		"auto-join": func(in *remediationapp.AcceptInput) { in.AutoJoin = true },
		"owners": func(in *remediationapp.AcceptInput) {
			in.Owners = []remediationapp.PartitionOwner{{Index: 0, UserID: &r.admin}}
		},
	} {
		_, err := asOwner(join, edit)
		assert.ErrorIs(t, err, remediationapp.ErrOwnerAcceptAsIs, name)
	}

	// The task is someone else's: refused.
	r.exec(`UPDATE remediation_tasks SET assignee_user_id = $2 WHERE id = $1`, task.String(), r.admin.String())
	_, err = asOwner(join, nil)
	assert.ErrorIs(t, err, remediationapp.ErrOwnerAcceptOwner)
	// Assigned to a group the member is not in: refused; once a member: allowed.
	r.exec(`UPDATE remediation_tasks SET assignee_user_id = NULL, assignee_group_id = $2 WHERE id = $1`, task.String(), r.group.String())
	_, err = asOwner(join, nil)
	assert.ErrorIs(t, err, remediationapp.ErrOwnerAcceptOwner)
	r.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, r.group.String(), r.member.String())

	// The member no longer owns the asset: refused.
	r.exec(`UPDATE asset_owners SET ownership_type = 'informed' WHERE asset_id = $1`, r.assetA.String())
	_, err = asOwner(join, nil)
	assert.ErrorIs(t, err, remediationapp.ErrOwnerAcceptAsset)
	r.exec(`UPDATE asset_owners SET ownership_type = 'secondary' WHERE asset_id = $1`, r.assetA.String())

	// Another tenant cannot reach it.
	_, err = r.sug.Accept(member, remediationapp.AcceptInput{TenantID: r.other, ID: join.ID, Version: join.Version, ActorID: &r.member, AsOwner: true},
		auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)

	jr, err := asOwner(join, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, jr.Joined)
	assert.Equal(t, "suggestion", r.taskMembers(task)[late])

	// A task route to the member's group, on the group's asset the member
	// can see: allowed through the group.
	r.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		r.member.String(), r.tenant.String(), r.assetB.String())
	r.exec(`UPDATE remediation_tasks SET assignee_user_id = $2, assignee_group_id = NULL WHERE id = $1`, task.String(), r.member.String())
	r.keyed(r.assetB, djangoKey, "P1")
	r.run()
	route := only(remediation.SuggestionTaskRoute)
	require.Len(t, route.Partitions, 1)
	assert.Equal(t, r.group.String(), route.Partitions[0].OwnerGroup)
	rr, err := asOwner(route, nil)
	require.NoError(t, err)
	require.Len(t, rr.TaskIDs, 1)

	// A member with write access accepting as such is unaffected (AsOwner false).
	assert.NotEqual(t, task, rr.TaskIDs[0])
}
