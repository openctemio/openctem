package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type pinsRecorder struct {
	tenant, command shared.ID
	pins            *scanrun.ContentPins
	calls           int
	err             error
}

func (r *pinsRecorder) RecordContentPins(_ context.Context, tenantID, commandID shared.ID, pins *scanrun.ContentPins) error {
	r.calls++
	r.tenant, r.command, r.pins = tenantID, commandID, pins
	return r.err
}

// A signed job records what it pinned on its command, under its own tenant:
// each pack with its version and digest, each generated list with its
// source and the organization lists it holds. The record never reaches the
// sensor: the delivered payload has no version, source or list names.
func TestSignJob_RecordsPinnedContent(t *testing.T) {
	tenant := shared.NewID()
	var got jobsign.Statement
	s := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		c := item("labels", digA)
		c.Version = "2026.10.1"
		return []protov2.JobContent{c}, []protov2.JobInput{
			{Slot: "labels", Purpose: "dns-labels", SHA256: strings.Repeat("c", 64), Lines: 12, Data: []byte("gz"), Source: scanrun.InputSourceLearned},
			{Slot: "labels", Purpose: "dns-labels", SHA256: strings.Repeat("d", 64), Lines: 3, Data: []byte("gz"), Source: scanrun.InputSourceOrganization,
				Lists: []protov2.InputListRef{{ID: "l1", Name: "secret-branch-names", Version: 4, SHA256: strings.Repeat("e", 64)}}},
		}, nil
	}), checkerOf{tenant.String(): {digA}})
	rec := &pinsRecorder{}
	s.contentRecorder = rec
	c := scanCmd(t, tenant, `{"scanner":"dnsx-enum","targets":["example.com"]}`, false)

	signed, err := s.signJob(context.Background(), shared.NewID().String(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	if rec.calls != 1 || rec.tenant != tenant || rec.command != c.ID {
		t.Fatalf("recorded %d times for %s/%s", rec.calls, rec.tenant, rec.command)
	}
	p := rec.pins
	if len(p.Packs) != 1 || p.Packs[0].Version != "2026.10.1" || p.Packs[0].Digest != digA || p.Packs[0].Pack != "wordlists-s" {
		t.Fatalf("packs %+v", p.Packs)
	}
	if len(p.Inputs) != 2 || p.Inputs[0].Source != scanrun.InputSourceLearned || p.Inputs[0].Lines != 12 ||
		p.Inputs[1].Source != scanrun.InputSourceOrganization || len(p.Inputs[1].Lists) != 1 || p.Inputs[1].Lists[0].Version != 4 {
		t.Fatalf("inputs %+v", p.Inputs)
	}
	var delivered string
	if err := json.Unmarshal(signed.Payload, &delivered); err != nil {
		delivered = string(signed.Payload)
	}
	for _, leak := range []string{"2026.10.1", "secret-branch-names", "organization", "learned"} {
		if strings.Contains(delivered, leak) {
			t.Fatalf("the delivered payload carries %q: %s", leak, delivered)
		}
	}
}

// Nothing is recorded for a job that is not signed, nor for one that pins
// nothing; a failed record does not stop the job.
func TestSignJob_ContentRecordOnlyForSignedJobs(t *testing.T) {
	tenant := shared.NewID()
	var got jobsign.Statement
	refused := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return []protov2.JobContent{item("labels", digB)}, nil, nil
	}), checkerOf{tenant.String(): {digA}})
	rec := &pinsRecorder{}
	refused.contentRecorder = rec
	if _, err := refused.signJob(context.Background(), "s", scanCmd(t, tenant, `{"targets":["example.com"]}`, false), false); err == nil {
		t.Fatal("a foreign digest was signed")
	}
	none := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) { return nil, nil, nil }), checkerOf{})
	none.contentRecorder = rec
	if _, err := none.signJob(context.Background(), "s", scanCmd(t, tenant, `{"targets":["example.com"]}`, false), false); err != nil {
		t.Fatal(err)
	}
	if rec.calls != 0 {
		t.Fatalf("recorded %d times", rec.calls)
	}
	failing := contentService(&got, planFn(func(PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
		return []protov2.JobContent{item("labels", digA)}, nil, nil
	}), checkerOf{tenant.String(): {digA}})
	failing.contentRecorder = &pinsRecorder{err: errors.New("db down")}
	if _, err := failing.signJob(context.Background(), "s", scanCmd(t, tenant, `{"targets":["example.com"]}`, false), false); err != nil {
		t.Fatalf("a failed record stopped the job: %v", err)
	}
}
