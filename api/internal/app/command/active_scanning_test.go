package command

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type passiveFeatures struct {
	denied map[shared.ID]bool
	err    error
}

func (f *passiveFeatures) Allowed(_ context.Context, t shared.ID, feature string) (bool, error) {
	if feature != limits.FeatureActiveScanning {
		return true, nil
	}
	if f.err != nil {
		return false, f.err
	}
	return !f.denied[t], nil
}

// passiveFailRepo records the commands failed at claim.
type passiveFailRepo struct {
	commanddom.Repository
	mu     sync.Mutex
	failed []shared.ID
}

func (r *passiveFailRepo) FailPending(_ context.Context, c *commanddom.Command, _ string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = append(r.failed, c.ID)
	return true, nil
}

func (r *passiveFailRepo) NarrowPendingPayload(context.Context, *commanddom.Command, json.RawMessage) (bool, error) {
	return true, nil
}

type passiveCodes struct{ got map[shared.ID]string }

func (c *passiveCodes) OnCommandFailed(_ context.Context, cmd *commanddom.Command, _, code string) {
	c.got[cmd.ID] = code
}

func passiveTestCmd(tenant shared.ID, tool string, gate *commanddom.DispatchGate) *commanddom.Command {
	p, _ := json.Marshal(map[string]any{"scanner": tool, "targets": []string{"a.example.com"}})
	return &commanddom.Command{ID: shared.NewID(), TenantID: tenant, Type: commanddom.CommandTypeScan, Payload: p, DispatchGate: gate}
}

func newPassiveSvc(f FeatureAllower) (*Service, *passiveFailRepo, *passiveCodes) {
	repo := &passiveFailRepo{}
	obs := &passiveCodes{got: map[shared.ID]string{}}
	s := &Service{repo: repo, activeScan: f, failures: obs, logger: logger.NewNop()}
	return s, repo, obs
}

// SECURITY: tenant A (denied) and tenant B (allowed) at the same time: A's
// active command is failed at claim and never handed out, B's is. A's
// passive command still goes out. Without the gate wired the scope gate is
// absent too, so the check does not depend on it.
func TestRecheck_PassiveOnlyIsPerOrganization(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	f := &passiveFeatures{denied: map[shared.ID]bool{a: true}}
	s, repo, obs := newPassiveSvc(f)
	ctx := context.Background()

	aActive := passiveTestCmd(a, "nuclei", &commanddom.DispatchGate{Tier: 1})
	aPassive := passiveTestCmd(a, "subfinder", &commanddom.DispatchGate{Tier: 0, Passive: true})
	out := s.recheckScope(ctx, a, nil, []*commanddom.Command{aActive, aPassive})
	require.Len(t, out, 1)
	assert.Equal(t, aPassive.ID, out[0].ID)
	assert.Equal(t, FailureActiveScanningNotEntitled, obs.got[aActive.ID])
	assert.Equal(t, []shared.ID{aActive.ID}, repo.failed)

	bActive := passiveTestCmd(b, "nuclei", &commanddom.DispatchGate{Tier: 1})
	out = s.recheckScope(ctx, b, nil, []*commanddom.Command{bActive})
	require.Len(t, out, 1, "the allowed organization's active command runs")
}

// SECURITY: the tier is computed on the server. A stored record that says
// tier 0, or a command without one, cannot carry an active tool; the tool's
// own tier (and a probing command type) counts.
func TestRecheck_PassiveOnlyForgedTier(t *testing.T) {
	a := shared.NewID()
	s, _, obs := newPassiveSvc(&passiveFeatures{denied: map[shared.ID]bool{a: true}})
	ctx := context.Background()
	forged := passiveTestCmd(a, "nuclei", &commanddom.DispatchGate{Tier: 0, Passive: true})
	noRecord := passiveTestCmd(a, "nuclei", nil)
	custom := passiveTestCmd(a, "subfinder", &commanddom.DispatchGate{Tier: 0})
	custom.Payload = json.RawMessage(`{"scanner":"subfinder","targets":["a.example.com"],"custom_templates":[{"id":"x"}]}`)
	retest := &commanddom.Command{ID: shared.NewID(), TenantID: a, Type: commanddom.CommandTypeRetest, Payload: json.RawMessage(`{"targets":["a.example.com"]}`)}
	validate := &commanddom.Command{ID: shared.NewID(), TenantID: a, Type: commanddom.CommandTypeValidate, Payload: json.RawMessage(`{"targets":["a.example.com"]}`)}
	out := s.recheckScope(ctx, a, nil, []*commanddom.Command{forged, noRecord, custom, retest, validate})
	assert.Empty(t, out)
	for _, c := range []*commanddom.Command{forged, noRecord, custom, retest, validate} {
		assert.Equal(t, FailureActiveScanningNotEntitled, obs.got[c.ID], string(c.Type))
	}
}

// SECURITY: an unreadable entitlement keeps a probe queued (never handed
// out, never failed for good) and does not touch passive work.
func TestRecheck_PassiveOnlyFailsClosed(t *testing.T) {
	a := shared.NewID()
	s, repo, _ := newPassiveSvc(&passiveFeatures{err: errors.New("db down")})
	active := passiveTestCmd(a, "nuclei", &commanddom.DispatchGate{Tier: 1})
	passive := passiveTestCmd(a, "subfinder", &commanddom.DispatchGate{Tier: 0, Passive: true})
	out := s.recheckScope(context.Background(), a, nil, []*commanddom.Command{active, passive})
	require.Len(t, out, 1)
	assert.Equal(t, passive.ID, out[0].ID)
	assert.Empty(t, repo.failed)
}

// SECURITY: a claim by id (acknowledge) is refused too, with its own error.
func TestRecheckOne_PassiveOnly(t *testing.T) {
	a := shared.NewID()
	s, _, _ := newPassiveSvc(&passiveFeatures{denied: map[shared.ID]bool{a: true}})
	_, err := s.recheckOne(context.Background(), shared.NewID(), passiveTestCmd(a, "nuclei", &commanddom.DispatchGate{Tier: 1}))
	require.Error(t, err)
	got, err := s.recheckOne(context.Background(), shared.NewID(), passiveTestCmd(a, "subfinder", &commanddom.DispatchGate{Tier: 0, Passive: true}))
	require.NoError(t, err)
	require.NotNil(t, got)
}

// SECURITY: the sensor-side gate refuses the same for the organization's own
// sensor and for a shared one (the gate is built per organization on both
// paths), also a tool the contract raises above passive, and explains why.
func TestDispatchGate_PassiveOnly(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	s, _, _ := newPassiveSvc(&passiveFeatures{denied: map[shared.ID]bool{a: true}})
	ctx := context.Background()
	active := passiveTestCmd(a, "nuclei", &commanddom.DispatchGate{Tier: 1})
	passive := passiveTestCmd(a, "subfinder", &commanddom.DispatchGate{Tier: 0})

	own := s.gateWith(ctx, a, gateSubject{}, []*commanddom.Command{active, passive})
	r := own.refusal(active)
	require.NotNil(t, r)
	assert.Equal(t, RuleActiveScanning, r.Rule)
	assert.Equal(t, commanddom.PlacementActiveScanning, gateReason(r))
	assert.Nil(t, own.refusal(passive))

	// Another organization's gate, in the same service, does not refuse.
	other := s.gateWith(ctx, b, gateSubject{}, []*commanddom.Command{passiveTestCmd(b, "nuclei", &commanddom.DispatchGate{Tier: 1})})
	assert.Nil(t, other.refusal(passiveTestCmd(b, "nuclei", &commanddom.DispatchGate{Tier: 1})))

	// An unreadable entitlement refuses a probe, not passive work.
	s2, _, _ := newPassiveSvc(&passiveFeatures{err: errors.New("down")})
	g := s2.gateWith(ctx, a, gateSubject{}, nil)
	assert.NotNil(t, g.refusal(active))
	assert.Nil(t, g.refusal(passive))
}

// The one entitlement service the server passes to WithSharedLimits is the
// active scanning gate too: if it stopped being a FeatureAllower this would
// not compile, so the gate cannot be lost silently.
func TestWithSharedLimits_WiresActiveScanning(t *testing.T) {
	var _ FeatureAllower = (*entitlement.Service)(nil)
	var _ SharedLimitSource = (*entitlement.Service)(nil)
	s := &Service{}
	WithSharedLimits(&entitlement.Service{})(s)
	require.NotNil(t, s.activeScan)
}
