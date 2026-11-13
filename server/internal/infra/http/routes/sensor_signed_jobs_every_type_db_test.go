package routes

// Every command type a sensor can be handed is signed when the platform
// advertises signed_jobs (docs/architecture/job-signing.md): a sensor that
// pinned the job signer refuses an unsigned command, so a type that skipped
// the signer would never run there. The test ranges over
// commanddom.CommandTypes(), which a guard test keeps complete. An analysis
// job goes only to an AI worker, so that type is pinned to a second sensor
// on the ai-worker grant.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/command"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/jobsign"
)

func TestSignedJobs_EveryCommandTypeIsSigned(t *testing.T) {
	fake, pub := newFakeSigner(t)
	h := newCtlHarness(t, command.WithJobSigner(fake), command.WithGrants(postgres.NewSensorGrantRepository(openSharedTestDB(t)), nil))
	s := h.newSensor(h.tenantID, "every-type")
	h.setMaxJobs(s.id, 100)
	h.legacyBroadGrant(s)
	w := h.newSensor(h.tenantID, "example-worker")
	h.setMaxJobs(w.id, 100)
	h.aiWorkerGrant(w)
	sensorOf := map[string]ctlSensor{}

	// One command of each type, pinned to the sensor, half claimed with
	// claim-N and half by id: both delivery paths sign.
	types := commanddom.CommandTypes()
	byID := map[string]commanddom.CommandType{}
	for _, ct := range types {
		to, body := s, json.RawMessage(`{"scanner":"semgrep","target":"."}`)
		if ct == commanddom.CommandTypeAnalyze {
			to, body = w, json.RawMessage(`{"job":{"contract":"openctem.analyze/v1"},"required_capabilities":[]}`)
		}
		c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: h.tenantID, SensorID: to.id,
			Type: string(ct), Priority: "normal", Payload: body, ExpiresIn: 3600})
		if err != nil {
			t.Fatalf("create %s: %v", ct, err)
		}
		byID[c.ID.String()] = ct
		sensorOf[c.ID.String()] = to
	}

	check := func(path string, c wireCommand) {
		t.Helper()
		ct, ok := byID[c.ID]
		if !ok {
			t.Fatalf("%s handed out unknown command %s", path, c.ID)
		}
		if len(c.SignedJob) == 0 {
			t.Fatalf("%s: command type %s handed out without signed_job", path, ct)
		}
		st, err := jobsign.Verify(c.SignedJob, []ed25519.PublicKey{pub})
		if err != nil {
			t.Fatalf("%s: signed_job of type %s: %v", path, ct, err)
		}
		if st.CommandType != string(ct) || st.CommandID != c.ID || st.SensorID != sensorOf[c.ID].id || st.TenantID != h.tenantID {
			t.Fatalf("%s: statement %+v does not describe the %s command %s", path, st, ct, c.ID)
		}
		if st.PayloadSHA256 != jobsign.PayloadDigest(c.Payload) {
			t.Fatalf("%s: payload digest of type %s does not match the payload bytes", path, ct)
		}
	}

	// Claim by id for the first half.
	half := map[string]bool{}
	for id := range byID {
		if len(half) >= len(byID)/2 {
			break
		}
		half[id] = true
		resp, raw := h.call(sensorOf[id].key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
		h.want(resp, raw, 200, "")
		check("claim by id", decodeAs[wireCommand](t, raw))
	}

	// Claim-N for the rest.
	got := map[string]bool{}
	for _, by := range []ctlSensor{s, w} {
		resp, raw := h.call(by.key, http.MethodGet, "/api/v2/sensor/commands?limit=100", nil, capacityHeader...)
		h.want(resp, raw, 200, "")
		for _, c := range decodeAs[wireCommandList](t, raw).Commands {
			check("claim-N", c)
			got[c.ID] = true
		}
	}
	for id, ct := range byID {
		if !half[id] && !got[id] {
			t.Errorf("claim-N did not hand out the %s command %s", ct, id)
		}
	}
}
