package command

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// replayRepo serves one stored command.
type replayRepo struct {
	commanddom.Repository
	cmd *commanddom.Command
}

func (r replayRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*commanddom.Command, error) {
	cp := *r.cmd
	return &cp, nil
}

type replayRules struct{}

func (replayRules) JobRules(context.Context, shared.ID, []string, time.Time) (*bp.JobRules, error) {
	return &bp.JobRules{Headers: map[string]string{"X-Bug-Bounty": "researcher"}, UserAgent: "program-ua", RateLimit: 5, Programs: []string{"p1"}}, nil
}

type replaySettings struct{}

func (replaySettings) ToolSettingsLayers(context.Context, shared.ID, shared.ID, string) (map[string]any, map[string]any, error) {
	return map[string]any{"rate": 10}, map[string]any{"threads": 2}, nil
}

type replayTemplates struct{}

func (replayTemplates) SignTemplates(_, _, _ string, payload json.RawMessage) json.RawMessage {
	var f map[string]json.RawMessage
	_ = json.Unmarshal(payload, &f)
	f["template_signatures"] = json.RawMessage(`["sig-1"]`)
	b, _ := json.Marshal(f)
	return b
}

type replaySensors struct{ s *sensordom.Sensor }

func (r replaySensors) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*sensordom.Sensor, error) {
	return r.s, nil
}

// The repeat of a claim hands out exactly what the first delivery (poll or
// claim-N) did, and the signature statement covers that payload: a job never
// runs without its program rules, HTTP policy, tool settings or template
// signatures because the sensor claimed it by id.
func TestClaimReplayDeliversTheFirstDeliveryPayload(t *testing.T) {
	tid, sid := shared.NewID(), shared.NewID()
	stored := &commanddom.Command{ID: shared.NewID(), TenantID: tid, Type: commanddom.CommandTypeScan,
		Status: commanddom.CommandStatusAcknowledged, SensorID: &sid,
		Payload: json.RawMessage(`{"scanner":"nuclei","targets":["app.example.com"],"http_policy":{"user_agent":"creator"}}`)}
	var st jobsign.Statement
	sen := &sensordom.Sensor{}
	sen.Reported.Capabilities = []string{sensordom.CapabilityHTTPIdentity}
	s := &Service{
		repo: replayRepo{cmd: stored}, logger: logger.NewNop(), now: time.Now,
		jobs: capturingSigner{got: &st}, programRules: replayRules{}, toolSettings: replaySettings{},
		templates: replayTemplates{}, sensors: replaySensors{sen},
		httpPolicy: fakeHTTPPolicy{pol: sensordom.ToolHTTPPolicy{UserAgent: "corp-scan"}},
	}

	// First delivery, as Poll builds it.
	first, err := s.deliver(context.Background(), sid.String(), []*commanddom.Command{stored}, map[shared.ID]*bp.JobRules{stored.ID: {
		Headers: map[string]string{"X-Bug-Bounty": "researcher"}, UserAgent: "program-ua", RateLimit: 5, Programs: []string{"p1"}}},
		map[shared.ID]settingsLayers{stored.ID: {Tenant: map[string]any{"rate": 10}, Sensor: map[string]any{"threads": 2}}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.Transition(context.Background(), TransitionClaim,
		TransitionInput{TenantID: tid.String(), SensorID: sid.String(), CommandID: stored.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Replayed {
		t.Fatal("expected a replay")
	}
	var got, want map[string]json.RawMessage
	var inner json.RawMessage
	// signJob wraps the payload as a JSON string (DeliveryPayload).
	if err := json.Unmarshal(res.Command.Payload, &inner); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(inner, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(first[0].Payload, &want); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"http_policy", settingsLayersField, "template_signatures"} {
		if len(got[k]) == 0 || !sameJSON(got[k], want[k]) {
			t.Errorf("%s: replay %s, first delivery %s", k, got[k], want[k])
		}
	}
	if string(got["http_policy"]) == string(want["http_policy"]) && !json.Valid(got["http_policy"]) {
		t.Fatal("invalid http_policy")
	}
	var hp map[string]any
	_ = json.Unmarshal(got["http_policy"], &hp)
	if hp["user_agent"] != "program-ua" {
		t.Errorf("the program's User-Agent is missing from the replay: %s", got["http_policy"])
	}
	if st.PayloadSHA256 != jobsign.PayloadDigest(DeliveryPayload(first[0].Payload)) {
		t.Error("the signed statement does not cover the first delivery's payload")
	}
	if string(stored.Payload) != `{"scanner":"nuclei","targets":["app.example.com"],"http_policy":{"user_agent":"creator"}}` {
		t.Error("the stored command was changed")
	}
}
