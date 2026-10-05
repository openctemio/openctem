package unit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-040 §5.7 on the platform: a tenant can keep jobs with private targets
// away from sensors that enforce no local policy (owner decision Q3 (a)),
// and jobs a sensor refused under its policy are reported (detection A11).

type policySensorLookup struct{ sensors map[shared.ID]*sensor.Sensor }

func (l policySensorLookup) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	if a, ok := l.sensors[id]; ok && a.TenantID != nil && *a.TenantID == tenantID {
		return a, nil
	}
	return nil, sensor.ErrSensorNotFound
}

type privatePolicy struct {
	required bool
	err      error
}

func (p privatePolicy) RequiresLocalPolicyForPrivateTargets(context.Context, shared.ID) (bool, error) {
	return p.required, p.err
}

type refusalRecorder struct{ calls []string }

func (r *refusalRecorder) ObserveLocalPolicyRefusal(_ context.Context, _, _ shared.ID, commandID, msg string) {
	r.calls = append(r.calls, commandID+"|"+msg)
}

func pendingCmd(repo *cmdMockRepo, tenantID shared.ID, payload string) *commanddom.Command {
	c := &commanddom.Command{ID: shared.NewID(), TenantID: tenantID, Type: commanddom.CommandTypeScan,
		Status: commanddom.CommandStatusPending, Payload: json.RawMessage(payload)}
	repo.commands[c.ID.String()] = c
	return c
}

func TestHasPrivateTarget(t *testing.T) {
	for payload, want := range map[string]bool{
		`{"target":"203.0.113.9"}`:                         false,
		`{"target":"10.1.2.3"}`:                            true,
		`{"targets":["198.51.100.1","192.168.1.0/24"]}`:    true,
		`{"targets":["0.0.0.0/0"]}`:                        true, // overlaps private space
		`{"target":"https://intranet.corp/login"}`:         true,
		`{"target":"https://example.com:8443/"}`:           false,
		`{"target":"db.internal:5432"}`:                    true,
		`{"target":"[fd00::1]:443"}`:                       true,
		`{"target":{"address":"172.16.5.4:22"}}`:           true,
		`{"target":{"address":"https://app.example.org"}}`: false,
		`{"target":"/scan/repo"}`:                          false, // a code scan path
		`{"target":"nginx:latest"}`:                        false, // an image reference
		`{"target":42}`:                                    true,  // unreadable: fail closed
		`not json`:                                         true,
		``:                                                 false,
	} {
		if got := command.HasPrivateTarget(json.RawMessage(payload)); got != want {
			t.Errorf("%s: %v, want %v", payload, got, want)
		}
	}
}

func TestPoll_WithholdsPrivateTargetsFromSensorsWithoutPolicy(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	noPolicy := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID}
	absent := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent}}
	enforced := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced}}
	paused := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced, KillSwitch: true}}
	lookup := policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{noPolicy.ID: noPolicy, absent.ID: absent, enforced.ID: enforced, paused.ID: paused}}

	repo := newCmdMockRepo()
	public := pendingCmd(repo, tenantID, `{"scanner":"nuclei","target":"203.0.113.9"}`)
	private := pendingCmd(repo, tenantID, `{"scanner":"nuclei","targets":["10.20.1.0/24"]}`)

	poll := func(svc *command.Service, a *sensor.Sensor) map[shared.ID]bool {
		cmds, err := svc.Poll(ctx, command.PollInput{TenantID: tenantID.String(), SensorID: a.ID.String(), Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		got := map[shared.ID]bool{}
		for _, c := range cmds {
			got[c.ID] = true
		}
		return got
	}

	on := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithPrivateTargetPolicy(privatePolicy{required: true}))
	for _, a := range []*sensor.Sensor{noPolicy, absent} {
		if got := poll(on, a); !got[public.ID] || got[private.ID] {
			t.Errorf("sensor %+v: polled %v, want only the public command", a.LocalPolicy, got)
		}
	}
	// A sensor whose owner engaged the kill switch runs no job at all, so
	// it is offered none (research/25 §3.6).
	if got := poll(on, paused); len(got) != 0 {
		t.Errorf("kill switch engaged: polled %v, want nothing", got)
	}
	if got := poll(on, enforced); !got[public.ID] || !got[private.ID] {
		t.Errorf("enforced policy: polled %v, want both", got)
	}

	// The switch off (the default): every sensor sees both, as before.
	off := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithPrivateTargetPolicy(privatePolicy{}))
	if got := poll(off, noPolicy); !got[public.ID] || !got[private.ID] {
		t.Errorf("switch off: polled %v, want both", got)
	}
	// The tenant setting cannot be read: fail closed.
	broken := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithPrivateTargetPolicy(privatePolicy{err: errors.New("db down")}))
	if got := poll(broken, enforced); got[private.ID] {
		t.Errorf("unreadable tenant setting: private target offered")
	}

	// A claim by id is refused the same way, as "claimed" (409), and the
	// command stays pending for a sensor that qualifies.
	_, err := on.Acknowledge(ctx, tenantID.String(), noPolicy.ID.String(), private.ID.String())
	if !errors.Is(err, command.ErrLocalPolicyRequired) || !errors.Is(err, command.ErrCommandClaimed) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("claim without a policy: %v", err)
	}
	if repo.commands[private.ID.String()].Status != commanddom.CommandStatusPending {
		t.Fatal("the refused claim changed the command")
	}
	if _, err := on.Acknowledge(ctx, tenantID.String(), noPolicy.ID.String(), public.ID.String()); err != nil {
		t.Fatalf("public command: %v", err)
	}
	if _, err := on.Acknowledge(ctx, tenantID.String(), enforced.ID.String(), private.ID.String()); err != nil {
		t.Fatalf("enforced policy: %v", err)
	}
}

func TestFail_ReportsRefusalsToTheObserver(t *testing.T) {
	ctx := context.Background()
	tenantID, sensorID := shared.NewID(), shared.NewID()
	repo := newCmdMockRepo()
	rec := &refusalRecorder{}
	svc := command.NewService(repo, newCmdTestLogger(), command.WithRefusalObserver(rec))
	c := pendingCmd(repo, tenantID, `{"scanner":"nuclei","target":"203.0.113.9"}`)
	c.Status = commanddom.CommandStatusRunning
	c.SensorID = &sensorID

	msg := "refused by local policy: targets.deny: 203.0.113.9 is in 203.0.113.0/24"
	if _, err := svc.Fail(ctx, command.FailInput{TenantID: tenantID.String(), SensorID: sensorID.String(), CommandID: c.ID.String(), ErrorMessage: msg}); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != c.ID.String()+"|"+msg {
		t.Fatalf("observer calls %v", rec.calls)
	}
}
