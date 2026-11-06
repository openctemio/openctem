package scim

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// A SCIM group stores only the organization's own members. An id of a
// person outside the organization (a member of another organization, or any
// account on the platform) is dropped on every write path, so it can neither
// raise that person's role the day they join nor confirm that the account
// exists.
func TestGroupMembers_OutsidersAreNotStored(t *testing.T) {
	ctx := context.Background()
	writes := map[string]func(f *groupFixture, insider, outsider shared.ID) []shared.ID{
		"create": func(f *groupFixture, insider, outsider shared.ID) []shared.ID {
			return f.group("viewer", insider, outsider).Members()
		},
		"replace": func(f *groupFixture, insider, outsider shared.ID) []shared.ID {
			g := f.group("viewer")
			out, err := f.svc.Replace(ctx, f.tenant, g.ID(), GroupInput{DisplayName: "viewer", MemberIDs: []shared.ID{insider, outsider}})
			if err != nil {
				t.Fatal(err)
			}
			return out.Members()
		},
		"patch add": func(f *groupFixture, insider, outsider shared.ID) []shared.ID {
			g := f.group("viewer")
			out, err := f.svc.PatchMembers(ctx, f.tenant, g.ID(), []shared.ID{insider, outsider}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return out.Members()
		},
		"patch replace": func(f *groupFixture, insider, outsider shared.ID) []shared.ID {
			g := f.group("viewer")
			out, err := f.svc.ReplaceMembers(ctx, f.tenant, g.ID(), []shared.ID{insider, outsider})
			if err != nil {
				t.Fatal(err)
			}
			return out.Members()
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			f := newGroupFixture(t)
			insider := f.member(tenantdom.RoleMember)
			// A member of another organization: known to the store, but not here.
			outsider := shared.NewID()
			other, err := tenantdom.NewMembership(outsider, shared.NewID(), tenantdom.RoleAdmin, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.members.byUser[outsider] = other
			got := write(f, insider, outsider)
			if len(got) != 1 || got[0] != insider {
				t.Fatalf("stored members = %v, want only the organization's member %v", got, insider)
			}
		})
	}
}
