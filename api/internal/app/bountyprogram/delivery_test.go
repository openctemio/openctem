package bountyprogram

import (
	"context"
	"errors"
	"strings"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeDeliveryStore struct {
	org      map[shared.ID]bool
	channels map[shared.ID]map[shared.ID]bool
	known    map[shared.ID]bool // the tenant's notification integrations
}

func newFakeDeliveryStore() *fakeDeliveryStore {
	return &fakeDeliveryStore{org: map[shared.ID]bool{}, channels: map[shared.ID]map[shared.ID]bool{}, known: map[shared.ID]bool{}}
}

func (f *fakeDeliveryStore) Channels(_ context.Context, _, programID shared.ID) ([]bp.Channel, error) {
	out := []bp.Channel{}
	for id := range f.channels[programID] {
		out = append(out, bp.Channel{IntegrationID: id})
	}
	return out, nil
}

func (f *fakeDeliveryStore) AttachChannel(_ context.Context, _, programID, integrationID shared.ID, _ *shared.ID) error {
	if !f.known[integrationID] {
		return bp.ErrChannelNotFound
	}
	if f.channels[programID] == nil {
		f.channels[programID] = map[shared.ID]bool{}
	}
	f.channels[programID][integrationID] = true
	return nil
}

func (f *fakeDeliveryStore) DetachChannel(_ context.Context, _, programID, integrationID shared.ID) error {
	if !f.channels[programID][integrationID] {
		return bp.ErrChannelNotFound
	}
	delete(f.channels[programID], integrationID)
	return nil
}

func (f *fakeDeliveryStore) OrgChannels(_ context.Context, _, programID shared.ID) (bool, error) {
	return f.org[programID], nil
}

func (f *fakeDeliveryStore) SetOrgChannels(_ context.Context, _, programID shared.ID, enabled bool) error {
	f.org[programID] = enabled
	return nil
}

func TestProgramDeliverySettings(t *testing.T) {
	svc, _, _, tenant, member, p := privateFixture(t, true)
	st := newFakeDeliveryStore()
	svc.SetDeliveryStore(st)
	ctx := context.Background()
	stranger := shared.NewID() // a full-data administrator, not a member
	slack := shared.NewID()
	st.known[slack] = true

	// A non-member administrator cannot see or change the program's channels.
	if _, _, err := svc.Delivery(ctx, tenant, stranger, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stranger reads delivery: %v", err)
	}
	if _, err := svc.AttachChannel(ctx, tenant, stranger, p.ID, slack); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stranger attaches: %v", err)
	}
	if _, _, err := svc.SetOrgChannels(ctx, tenant, stranger, p.ID, true, "a long enough reason"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stranger opts in: %v", err)
	}

	// A member attaches a notification integration of the tenant; another
	// tenant's (unknown) integration is not found.
	if _, err := svc.AttachChannel(ctx, tenant, member, p.ID, slack); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AttachChannel(ctx, tenant, member, p.ID, shared.NewID()); !errors.Is(err, bp.ErrChannelNotFound) {
		t.Fatalf("unknown integration: %v", err)
	}
	_, d, err := svc.Delivery(ctx, tenant, member, p.ID)
	if err != nil || len(d.Channels) != 1 || d.Channels[0].IntegrationID != slack || d.OrgChannels {
		t.Fatalf("delivery = %+v %v", d, err)
	}

	// Only an owner turns organization channels on, with a reason.
	if _, _, err := svc.SetOrgChannels(ctx, tenant, member, p.ID, true, "a long enough reason"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("member opts in: %v", err)
	}
	owner := asOwner(ctx)
	if _, _, err := svc.SetOrgChannels(owner, tenant, shared.NewID(), p.ID, true, "short"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("short reason: %v", err)
	}
	if _, _, err := svc.SetOrgChannels(owner, tenant, shared.NewID(), p.ID, true, strings.Repeat("x", maxOptInReason+1)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("long reason: %v", err)
	}
	if st.org[p.ID] {
		t.Fatal("opt-in stored without a valid reason")
	}
	_, reason, err := svc.SetOrgChannels(owner, tenant, shared.NewID(), p.ID, true, "  incident bridge needs it  ")
	if err != nil || !st.org[p.ID] || reason != "incident bridge needs it" {
		t.Fatalf("owner opt-in: %v %v %q", err, st.org[p.ID], reason)
	}
	// Turning it off needs no reason.
	if _, _, err := svc.SetOrgChannels(owner, tenant, shared.NewID(), p.ID, false, ""); err != nil || st.org[p.ID] {
		t.Fatalf("owner opt-out: %v", err)
	}

	// Detaching narrows; a second detach is not found.
	if _, err := svc.DetachChannel(ctx, tenant, member, p.ID, slack); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DetachChannel(ctx, tenant, member, p.ID, slack); !errors.Is(err, bp.ErrChannelNotFound) {
		t.Fatalf("second detach: %v", err)
	}

	// Without the store the endpoints answer not found.
	svc.SetDeliveryStore(nil)
	if _, _, err := svc.Delivery(ctx, tenant, member, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no store: %v", err)
	}
}

func TestReadablePrograms(t *testing.T) {
	svc, _, _, tenant, member, p := privateFixture(t, true)
	ctx := context.Background()
	stranger := shared.NewID() // a full-data integration admin, not a member
	ids := []shared.ID{p.ID}

	got, err := svc.ReadablePrograms(ctx, tenant, member, ids)
	if err != nil || !got[p.ID] {
		t.Fatalf("member: %v %v", got, err)
	}
	if got, err = svc.ReadablePrograms(ctx, tenant, stranger, ids); err != nil || got[p.ID] {
		t.Fatalf("stranger reads the program: %v %v", got, err)
	}
	if got, err = svc.ReadablePrograms(ctx, tenant, shared.ID{}, ids); err != nil || got[p.ID] {
		t.Fatalf("no actor reads the program: %v %v", got, err)
	}
	if got, err = svc.ReadablePrograms(asOwner(ctx), tenant, stranger, ids); err != nil || !got[p.ID] {
		t.Fatalf("owner: %v %v", got, err)
	}
	// A member of the program, asked about another tenant, reads nothing.
	if got, err = svc.ReadablePrograms(ctx, shared.NewID(), member, ids); err != nil || got[p.ID] {
		t.Fatalf("cross-tenant: %v %v", got, err)
	}
}
