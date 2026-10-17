package scanpolicy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memEgress is memShared with the egress store.
type memEgress struct {
	memShared
	egress    *SharedSensorsEgress
	egressVer int
	egressSet bool
}

func (m *memEgress) GetSharedSensorsEgress(context.Context) (SharedSensorsEgress, int, error) {
	if m.egress == nil {
		return SharedSensorsEgress{}, 0, ErrNotFound
	}
	return *m.egress, m.egressVer, nil
}

func (m *memEgress) SetSharedSensorsEgress(_ context.Context, v SharedSensorsEgress, expected int, _ string, _ time.Time) (int, error) {
	m.egressSet = true
	if expected != m.egressVer {
		return 0, ErrVersionConflict
	}
	m.egress, m.egressVer = &v, m.egressVer+1
	return m.egressVer, nil
}

// Only public addresses may be published: every internal range (ctis
// addrscope) is refused, also when a CIDR merely overlaps one or an IPv6
// address carries an internal IPv4 address.
func TestNormalizeSharedSensorsEgress_RefusesInternal(t *testing.T) {
	refused := []string{
		"10.0.0.1", "10.0.0.0/8", "172.16.5.4", "192.168.1.0/24", "127.0.0.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"8.0.0.0/4", // overlaps 10.0.0.0/8
		"0.0.0.0/0", // everything
		"::1", "fe80::1", "fd00:ec2::254", "fc00::/7", "::/0",
		"::ffff:10.0.0.1",    // IPv4-mapped private
		"64:ff9b::a9fe:a9fe", // NAT64 of the metadata address
		"2002:a00:1::1",      // 6to4 of 10.0.0.1
		"fe80::1%eth0",       // zone
		"not-an-ip", "1.2.3.4/33", "", "  ", "example.com",
	}
	for _, v := range refused {
		_, err := NormalizeSharedSensorsEgress(SharedSensorsEgress{Global: []string{v}})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (err %v)", v, err)
		}
		_, err = NormalizeSharedSensorsEgress(SharedSensorsEgress{Regions: map[string][]string{"eu": {v}}})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted in a region (err %v)", v, err)
		}
	}
}

func TestNormalizeSharedSensorsEgress_Canonical(t *testing.T) {
	got, err := NormalizeSharedSensorsEgress(SharedSensorsEgress{
		Global: []string{" 203.0.113.9 ", "198.51.100.77/24", "203.0.113.9", "8.8.8.8/32", "2001:db8::1/128"},
		Regions: map[string][]string{
			"eu-west-1": {"2001:db8:10::/48"},
			"empty":     {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := SharedSensorsEgress{
		Global:  []string{"198.51.100.0/24", "2001:db8::1", "203.0.113.9", "8.8.8.8"},
		Regions: map[string][]string{"eu-west-1": {"2001:db8:10::/48"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestNormalizeSharedSensorsEgress_Limits(t *testing.T) {
	for _, region := range []string{"", "eu west", "eu;rm -rf", strings.Repeat("a", 65), "<b>"} {
		if _, err := NormalizeSharedSensorsEgress(SharedSensorsEgress{Regions: map[string][]string{region: {"8.8.8.8"}}}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("region %q accepted: %v", region, err)
		}
	}
	many := make([]string, MaxEgressAddressesPerList+1)
	for i := range many {
		many[i] = fmt.Sprintf("8.8.%d.%d", i/250, i%250+1)
	}
	if _, err := NormalizeSharedSensorsEgress(SharedSensorsEgress{Global: many}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("too many addresses accepted: %v", err)
	}
	regions := map[string][]string{}
	for i := 0; i <= MaxEgressRegions; i++ {
		regions[fmt.Sprintf("r%d", i)] = []string{"8.8.8.8"}
	}
	if _, err := NormalizeSharedSensorsEgress(SharedSensorsEgress{Regions: regions}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("too many regions accepted: %v", err)
	}
}

// A change needs an administrator and a reason, refuses internal addresses
// before anything is written, stores the normalized list, writes a critical
// admin audit row and checks the version.
func TestUpdateSharedSensorsEgress(t *testing.T) {
	ctx := context.Background()
	repo := &memEgress{memShared: memShared{access: map[shared.ID]string{}}}
	audit := &auditRows{}
	svc := NewService(repo, audit, nil, nil, nil, logger.NewNop())
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)

	if v, ver, err := svc.SharedSensorsEgress(ctx); err != nil || ver != 0 || !v.Empty() || v.Global == nil || v.Regions == nil {
		t.Fatalf("nothing stored: %+v %d %v", v, ver, err)
	}
	if _, _, err := svc.UpdateSharedSensorsEgress(ctx, SharedSensorsEgress{Global: []string{"8.8.8.8"}}, 0, Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: %v", err)
	}
	if _, _, err := svc.UpdateSharedSensorsEgress(ctx, SharedSensorsEgress{Global: []string{"8.8.8.8"}}, 0, Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, _, err := svc.UpdateSharedSensorsEgress(ctx, SharedSensorsEgress{Global: []string{"10.1.2.3"}}, 0, Change{Actor: actor, Reason: "x"}); !errors.Is(err, shared.ErrValidation) ||
		repo.egressSet || len(audit.rows) != 0 {
		t.Fatalf("private address: %v set=%v audit=%d", err, repo.egressSet, len(audit.rows))
	}
	got, ver, err := svc.UpdateSharedSensorsEgress(ctx, SharedSensorsEgress{Global: []string{"203.0.113.5", "203.0.113.5"}}, 0, Change{Actor: actor, Reason: "new scanner range"})
	if err != nil || ver != 1 || !reflect.DeepEqual(got.Global, []string{"203.0.113.5"}) {
		t.Fatalf("update: %+v %d %v", got, ver, err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionSharedSensorsEgressChanged || audit.rows[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit: %+v", audit.rows)
	}
	if _, _, err := svc.UpdateSharedSensorsEgress(ctx, SharedSensorsEgress{}, 0, Change{Actor: actor, Reason: "x"}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
}
