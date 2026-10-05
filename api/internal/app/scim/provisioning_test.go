package scim

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeUserStore struct {
	byEmail map[string]*userdom.User
	byID    map[shared.ID]*userdom.User
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{byEmail: map[string]*userdom.User{}, byID: map[shared.ID]*userdom.User{}}
}
func (f *fakeUserStore) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}
func (f *fakeUserStore) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}
func (f *fakeUserStore) Create(_ context.Context, u *userdom.User) error {
	f.byEmail[u.Email()] = u
	f.byID[u.ID()] = u
	return nil
}
func (f *fakeUserStore) Update(_ context.Context, u *userdom.User) error {
	f.byEmail[u.Email()] = u
	f.byID[u.ID()] = u
	return nil
}

// memberStore implements both MembershipReader and MembershipManager over an
// in-memory map keyed by userID (tests use a single tenant).
type memberStore struct {
	byUser map[shared.ID]*tenantdom.Membership
}

func newMemberStore() *memberStore {
	return &memberStore{byUser: map[shared.ID]*tenantdom.Membership{}}
}
func (m *memberStore) GetMembership(_ context.Context, userID, _ shared.ID) (*tenantdom.Membership, error) {
	if mem, ok := m.byUser[userID]; ok {
		return mem, nil
	}
	return nil, shared.ErrNotFound
}
func (m *memberStore) ListMembersByTenant(_ context.Context, _ shared.ID) ([]*tenantdom.Membership, error) {
	out := make([]*tenantdom.Membership, 0, len(m.byUser))
	for _, mem := range m.byUser {
		out = append(out, mem)
	}
	return out, nil
}
func (m *memberStore) AddMember(_ context.Context, tenantID, userID shared.ID, role string) error {
	mem, err := tenantdom.NewMembership(userID, tenantID, tenantdom.Role(role), nil)
	if err != nil {
		return err
	}
	m.byUser[userID] = mem
	return nil
}
func (m *memberStore) find(membershipID shared.ID) *tenantdom.Membership {
	for _, mem := range m.byUser {
		if mem.ID() == membershipID {
			return mem
		}
	}
	return nil
}
func (m *memberStore) SuspendMember(_ context.Context, _, membershipID shared.ID) error {
	if mem := m.find(membershipID); mem != nil {
		return mem.Suspend(shared.NewID())
	}
	return errors.New("not found")
}
func (m *memberStore) ReactivateMember(_ context.Context, _, membershipID shared.ID) error {
	if mem := m.find(membershipID); mem != nil {
		return mem.Reactivate()
	}
	return errors.New("not found")
}
func (m *memberStore) OffboardMember(_ context.Context, _, membershipID shared.ID) error {
	if mem := m.find(membershipID); mem != nil {
		return mem.Offboard()
	}
	return errors.New("not found")
}

func newProvisioning() (*ProvisioningService, *fakeUserStore, *memberStore) {
	users := newFakeUserStore()
	members := newMemberStore()
	return NewProvisioningService(users, members, members, logger.NewNop()), users, members
}

func seedActiveMember(t *testing.T, users *fakeUserStore, members *memberStore, tenantID shared.ID, email string) shared.ID {
	t.Helper()
	u, err := userdom.New(email, "Seed User")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_ = users.Create(context.Background(), u)
	if err := members.AddMember(context.Background(), tenantID, u.ID(), "member"); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return u.ID()
}

func TestProvision_NewUser_CreatesUserAndMembership(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()

	res, created, err := svc.CreateOrActivate(context.Background(), tenantID, ProvisionInput{
		UserName: "Alice@Example.com", DisplayName: "Alice", Active: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if !created {
		t.Error("expected created=true for a new membership")
	}
	if !res.Active {
		t.Error("expected active resource")
	}
	if res.Email != "alice@example.com" {
		t.Errorf("email should be normalised lowercase, got %q", res.Email)
	}
	if _, ok := users.byEmail["alice@example.com"]; !ok {
		t.Error("user not created")
	}
	if len(members.byUser) != 1 {
		t.Errorf("membership count = %d, want 1", len(members.byUser))
	}
}

func TestProvision_ExistingActive_Idempotent(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	seedActiveMember(t, users, members, tenantID, "bob@example.com")

	_, created, err := svc.CreateOrActivate(context.Background(), tenantID, ProvisionInput{
		UserName: "bob@example.com", Active: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if created {
		t.Error("re-provisioning an existing member must not report created=true")
	}
	if len(members.byUser) != 1 {
		t.Errorf("membership count = %d, want 1 (no duplicate)", len(members.byUser))
	}
}

func TestProvision_Deactivate_SuspendsMembership(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	uid := seedActiveMember(t, users, members, tenantID, "carol@example.com")

	res, err := svc.SetActive(context.Background(), tenantID, uid, false)
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if res.Active {
		t.Error("resource should be inactive after deactivation")
	}
	if !members.byUser[uid].IsSuspended() {
		t.Error("membership should be suspended")
	}
}

func TestProvision_Reactivate(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	uid := seedActiveMember(t, users, members, tenantID, "dave@example.com")
	_ = members.byUser[uid].Suspend(shared.NewID())

	res, err := svc.SetActive(context.Background(), tenantID, uid, true)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if !res.Active {
		t.Error("resource should be active after reactivation")
	}
	if members.byUser[uid].IsSuspended() {
		t.Error("membership should no longer be suspended")
	}
}

// SCIM DELETE offboards; the tombstone is then invisible to SCIM (Get and
// SetActive answer not found), and re-provisioning the same person creates a
// fresh membership (re-join from zero) instead of reviving the old one.
func TestProvision_Deprovision_OffboardsAndReprovisionStartsFresh(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	uid := seedActiveMember(t, users, members, tenantID, "leaver@example.com")
	oldID := members.byUser[uid].ID()

	if err := svc.Deprovision(context.Background(), tenantID, uid); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if !members.byUser[uid].IsOffboarded() {
		t.Fatal("membership should be offboarded")
	}
	if _, err := svc.Get(context.Background(), tenantID, uid); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("Get of an offboarded member: want not found, got %v", err)
	}
	if _, err := svc.SetActive(context.Background(), tenantID, uid, true); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("SetActive(true) must not revive a tombstone, got %v", err)
	}
	if err := svc.Deprovision(context.Background(), tenantID, uid); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second deprovision: want not found, got %v", err)
	}

	// The account exists, so re-attaching it follows the newcomer rule: the
	// organization must own the email domain (else it must invite).
	if _, _, err := svc.CreateOrActivate(context.Background(), tenantID, ProvisionInput{
		UserName: "leaver@example.com", Active: true,
	}); !errors.Is(err, ErrExistingAccountNeedsInvite) {
		t.Fatalf("re-provision without a verified domain: want ErrExistingAccountNeedsInvite, got %v", err)
	}
	svc.SetDomainVerifier(staticVerifier{"example.com": true})
	_, created, err := svc.CreateOrActivate(context.Background(), tenantID, ProvisionInput{
		UserName: "leaver@example.com", Active: true,
	})
	if err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if !created {
		t.Error("re-provisioning an offboarded person must report created=true")
	}
	m := members.byUser[uid]
	if !m.IsActive() || m.ID() == oldID {
		t.Errorf("re-provision should add a fresh active membership (active=%v, sameID=%v)", m.IsActive(), m.ID() == oldID)
	}
}

func TestProvision_SetActive_NotMember(t *testing.T) {
	svc, _, _ := newProvisioning()
	_, err := svc.SetActive(context.Background(), shared.NewID(), shared.NewID(), false)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for non-member, got %v", err)
	}
}

func TestProvision_Get_NotMember(t *testing.T) {
	svc, _, _ := newProvisioning()
	_, err := svc.Get(context.Background(), shared.NewID(), shared.NewID())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestProvision_List_FilterByEmail(t *testing.T) {
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	seedActiveMember(t, users, members, tenantID, "erin@example.com")
	seedActiveMember(t, users, members, tenantID, "frank@example.com")

	list, total, err := svc.List(context.Background(), tenantID, "erin@example.com", 1, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].Email != "erin@example.com" {
		t.Fatalf("filter should return only erin, got total=%d list=%d", total, len(list))
	}

	all, allTotal, err := svc.List(context.Background(), tenantID, "", 1, 100)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if allTotal != 2 || len(all) != 2 {
		t.Fatalf("unfiltered list should return 2, got total=%d list=%d", allTotal, len(all))
	}
}

func TestProvision_List_CountZeroReturnsNoResources(t *testing.T) {
	// SCIM: count=0 means "return totalResults but no Resources".
	svc, users, members := newProvisioning()
	tenantID := shared.NewID()
	seedActiveMember(t, users, members, tenantID, "x@example.com")
	seedActiveMember(t, users, members, tenantID, "y@example.com")

	list, total, err := svc.List(context.Background(), tenantID, "", 1, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(list) != 0 {
		t.Errorf("count=0 must return no resources, got %d", len(list))
	}
}

func TestProvision_CreateInactive(t *testing.T) {
	svc, _, members := newProvisioning()
	tenantID := shared.NewID()
	active := false

	res, created, err := svc.CreateOrActivate(context.Background(), tenantID, ProvisionInput{
		UserName: "ghost@example.com", Active: active,
	})
	if err != nil {
		t.Fatalf("provision inactive: %v", err)
	}
	if !created {
		t.Error("expected created=true")
	}
	if res.Active {
		t.Error("resource should be inactive when provisioned with active=false")
	}
	for _, m := range members.byUser {
		if !m.IsSuspended() {
			t.Error("provisioned-inactive membership should be suspended")
		}
	}
}

type staticVerifier map[string]bool

func (v staticVerifier) IsVerifiedDomain(_ context.Context, _, domain string) (bool, error) {
	return v[domain], nil
}

// seedOutsideAccount creates an account that is not a member of the tenant
// under test (it belongs to some other organization).
func seedOutsideAccount(t *testing.T, users *fakeUserStore, email string) *userdom.User {
	t.Helper()
	u, err := userdom.New(email, "Victim")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_ = users.Create(context.Background(), u)
	return u
}

// An organization must not enroll someone else's existing account by email:
// attaching an existing account needs the person's consent (an invitation)
// unless the organization owns the email domain.
func TestProvision_ExistingAccountOutsideVerifiedDomain_Refused(t *testing.T) {
	for name, verifier := range map[string]DomainVerifier{
		"no verifier":         nil,
		"domain not verified": staticVerifier{"attacker.io": true},
	} {
		t.Run(name, func(t *testing.T) {
			svc, users, members := newProvisioning()
			if verifier != nil {
				svc.SetDomainVerifier(verifier)
			}
			seedOutsideAccount(t, users, "victim@corp.com")

			_, _, err := svc.CreateOrActivate(context.Background(), shared.NewID(), ProvisionInput{
				UserName: "victim@corp.com", Active: true,
			})
			if !errors.Is(err, ErrExistingAccountNeedsInvite) || !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("expected ErrExistingAccountNeedsInvite, got %v", err)
			}
			if len(members.byUser) != 0 {
				t.Fatal("no membership may be created for a refused provision")
			}
		})
	}
}

// On a domain the organization has DNS-verified, SCIM may attach the existing
// account (the organization owns that identity).
func TestProvision_ExistingAccountOnVerifiedDomain_Attached(t *testing.T) {
	svc, users, members := newProvisioning()
	svc.SetDomainVerifier(staticVerifier{"corp.com": true})
	u := seedOutsideAccount(t, users, "staff@corp.com")

	_, created, err := svc.CreateOrActivate(context.Background(), shared.NewID(), ProvisionInput{
		UserName: "staff@corp.com", Active: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if !created || members.byUser[u.ID()] == nil {
		t.Fatal("expected the existing account to be attached on a verified domain")
	}
}
