package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type planFn func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error)

func (f planFn) PinJobContent(_ context.Context, r PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
	return f(r)
}

// checkerOf allows exactly the listed digests for the listed tenants; a
// shared sensor's scope is keyed "instance".
type checkerOf map[string][]string

func (c checkerOf) Deliverable(_ context.Context, tenantID shared.ID, sharedSensor bool, digest string) (bool, error) {
	key := tenantID.String()
	if sharedSensor {
		key = "instance"
	}
	for _, d := range c[key] {
		if d == digest {
			return true, nil
		}
	}
	return false, nil
}

const (
	digA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func item(slot, digest string) protov2.JobContent {
	return protov2.JobContent{Slot: slot, Kind: "wordlist", Scope: "platform", Pack: "wordlists-s", Digest: digest, Signature: json.RawMessage(`{}`)}
}

func scanCmd(t *testing.T, tenant shared.ID, payload string, platform bool) *commanddom.Command {
	t.Helper()
	c, err := commanddom.NewCommand(tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, json.RawMessage(payload))
	if err != nil {
		t.Fatal(err)
	}
	if platform {
		if err := c.SetPlatformJob(50); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func contentService(got *jobsign.Statement, src ContentSource, chk ContentChecker) *Service {
	return &Service{jobs: capturingSigner{got: got}, logger: logger.NewNop(), now: time.Now, content: src, contentCheck: chk}
}

// A job's packs and generated lists are set on the copy the sensor gets, the
// signed statement lists each pack's slot and digest in payload order, and
// payload_sha256 covers the payload as delivered, content included.
func TestSignJob_PinsContentIntoThePayloadAndTheStatement(t *testing.T) {
	tenant := shared.NewID()
	var got jobsign.Statement
	s := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return []protov2.JobContent{item("labels", digA), item("params", digB)},
			[]protov2.JobInput{{Slot: "labels", Purpose: "dns-labels", SHA256: strings.Repeat("c", 64), Data: []byte("gz")}}, nil
	}), checkerOf{tenant.String(): {digA, digB}})
	c := scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, false)

	signed, err := s.signJob(context.Background(), shared.NewID().String(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []jobsign.ContentRef{{Slot: "labels", Digest: digA}, {Slot: "params", Digest: digB}}
	if len(got.Content) != 2 || got.Content[0] != want[0] || got.Content[1] != want[1] {
		t.Fatalf("statement content = %+v, want %+v", got.Content, want)
	}
	if got.PayloadSHA256 != jobsign.PayloadDigest(signed.Payload) {
		t.Errorf("payload_sha256 does not cover the delivered payload")
	}
	if refs := jobsign.PayloadContentRefs(signed.Payload); len(refs) != 2 || refs[0] != want[0] {
		t.Errorf("payload content = %+v", refs)
	}
	var p struct {
		Inputs []protov2.JobInput `json:"inputs"`
	}
	if err := json.Unmarshal(signed.Payload, &p); err != nil || len(p.Inputs) != 1 || p.Inputs[0].Purpose != "dns-labels" {
		t.Errorf("payload inputs = %+v, %v", p.Inputs, err)
	}
	// The stored command is not changed.
	if strings.Contains(string(c.Payload), "inputs") {
		t.Errorf("the stored command was modified: %s", c.Payload)
	}
}

// A digest the job's organization may not use is never signed, whatever put
// it in the plan: another organization's pack, a revoked one, an unknown one.
func TestSignJob_RefusesADigestOutsideTheOrganization(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	var got jobsign.Statement
	s := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return []protov2.JobContent{item("labels", digB)}, nil, nil // B's pack in A's job
	}), checkerOf{tenantA.String(): {digA}, tenantB.String(): {digB}})
	c := scanCmd(t, tenantA, `{"scanner":"dnsx","targets":["example.com"]}`, false)

	_, err := s.signJob(context.Background(), shared.NewID().String(), c, false)
	if !errors.Is(err, ErrJobNotSigned) || !errors.Is(err, ErrContentRefused) {
		t.Fatalf("err = %v, want a permanent content refusal that is not signed", err)
	}
	if got.CommandID != "" {
		t.Fatalf("the signer was asked to sign: %+v", got)
	}
}

// A shared job is checked against the instance scope: an organization's own
// pack is not deliverable to it even when the organization owns the digest.
func TestSignJob_SharedJobsMayPinPlatformPacksOnly(t *testing.T) {
	tenant := shared.NewID()
	plan := planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return []protov2.JobContent{item("labels", digA)}, nil, nil
	})
	chk := checkerOf{tenant.String(): {digA}, "instance": {digB}} // digA is the organization's own pack
	var got jobsign.Statement
	s := contentService(&got, plan, chk)
	if _, err := s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, true), false); !errors.Is(err, ErrContentRefused) {
		t.Fatalf("a tenant pack on a shared job: err = %v", err)
	}
	// Its own sensor may.
	if _, err := s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, false), false); err != nil {
		t.Fatalf("the organization's own job: %v", err)
	}
	// A platform pack is fine on a shared job.
	s = contentService(&got, planFn(func(r PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		if !r.Shared {
			t.Error("the plan was not told the job is shared")
		}
		return []protov2.JobContent{item("labels", digB)}, nil, nil
	}), chk)
	if _, err := s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, true), false); err != nil {
		t.Fatalf("a platform pack on a shared job: %v", err)
	}
}

// Content or inputs a creator wrote in the payload are removed: the members
// belong to the platform, with or without a source.
func TestSignJob_CreatorContentIsRemoved(t *testing.T) {
	tenant := shared.NewID()
	payload := `{"scanner":"dnsx","targets":["example.com"],` +
		`"content":[{"slot":"labels","scope":"platform","pack":"x","digest":"` + digB + `","signature":{}}],` +
		`"inputs":[{"slot":"labels","purpose":"dns-labels","sha256":"` + strings.Repeat("d", 64) + `","data_b64":"AA=="}]}`
	for name, src := range map[string]ContentSource{
		"no source":  nil,
		"empty plan": planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) { return nil, nil, nil }),
		"another plan": planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
			return []protov2.JobContent{item("labels", digA)}, nil, nil
		}),
	} {
		var got jobsign.Statement
		s := contentService(&got, src, checkerOf{tenant.String(): {digA}})
		signed, err := s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, payload, false), false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		refs := jobsign.PayloadContentRefs(signed.Payload)
		for _, r := range refs {
			if r.Digest == digB {
				t.Errorf("%s: the creator's pack reached the sensor's copy", name)
			}
		}
		if strings.Contains(string(signed.Payload), strings.Repeat("d", 64)) {
			t.Errorf("%s: the creator's inline list reached the sensor's copy", name)
		}
		if name == "another plan" && (len(got.Content) != 1 || got.Content[0].Digest != digA) {
			t.Errorf("%s: statement content = %+v", name, got.Content)
		}
		if name != "another plan" && len(got.Content) != 0 {
			t.Errorf("%s: statement content = %+v", name, got.Content)
		}
	}
}

// A transient failure to plan is not a permanent refusal: the claim is taken
// back and tried again.
func TestSignJob_PlanErrorsAreTransientUnlessRefused(t *testing.T) {
	tenant := shared.NewID()
	var got jobsign.Statement
	boom := errors.New("database down")
	s := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) { return nil, nil, boom }), checkerOf{})
	_, err := s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, false), false)
	if !errors.Is(err, ErrJobNotSigned) || errors.Is(err, ErrContentRefused) || !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	s = contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return nil, nil, &ContentRefusedError{Reason: "no pack"}
	}), checkerOf{})
	_, err = s.signJob(context.Background(), shared.NewID().String(), scanCmd(t, tenant, `{"scanner":"dnsx","targets":["example.com"]}`, false), false)
	if !errors.Is(err, ErrContentRefused) {
		t.Fatalf("err = %v", err)
	}
}

// Commands other than scan and retest carry no content members of the
// platform's, and their payloads are left as they are.
func TestSignJob_OtherCommandsAreUntouched(t *testing.T) {
	var got jobsign.Statement
	called := false
	s := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		called = true
		return []protov2.JobContent{item("labels", digA)}, nil, nil
	}), checkerOf{})
	c, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal,
		json.RawMessage(`{"content":"keep me","targets":["example.com"]}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.signJob(context.Background(), shared.NewID().String(), c, false)
	if err != nil || called || !strings.Contains(string(signed.Payload), `"content":"keep me"`) || len(got.Content) != 0 {
		t.Fatalf("err %v, planned %v, payload %s, content %+v", err, called, signed.Payload, got.Content)
	}
}
