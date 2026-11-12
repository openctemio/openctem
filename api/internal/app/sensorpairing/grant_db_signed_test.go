package sensorpairing_test

// The signed pairing grant (research 452 N3): someone in the middle of the
// first pairing relays the start untouched, so the fingerprint the
// administrator compares matches, and swaps what the sensor pins later. The
// approval and confirm answers carry a grant signed with the pairing key of
// the start answer, bound to the request, the sensor key and its nonce.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestPairing_AnswersCarryASignedGrant_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-grant")
	keyset := json.RawMessage(`{"payloadType":"application/vnd.openctem.keyset.v1+json","payload":"e30","signatures":[]}`)
	jobs := &protov2.SignedJobs{PayloadType: "application/vnd.openctem.job.v1+json", KeySet: keyset,
		Keys: []protov2.SignedJobKey{{KeyID: "SHA256:" + string(bytes.Repeat([]byte("ab"), 32)), Algorithm: "ed25519", PublicKey: "AQ=="}}}
	f.svc.SetSignedJobs(func(context.Context) *protov2.SignedJobs { return jobs })
	anchor := "sha256:" + string(bytes.Repeat([]byte("0f"), 32))
	f.svc.SetTLSAnchors(func() []string { return []string{anchor} })

	s, other := newSensor(1), newSensor(2)
	f.start(s, "", "")
	f.start(other, "", "")
	f.reveal(s)
	f.reveal(other)
	id, _ := shared.IDFromString(s.resp.PairingID)
	otherID, _ := shared.IDFromString(other.resp.PairingID)

	// Pending: no identity, nothing signed.
	if st := f.status(s); st.Grant != nil || st.Identity != nil {
		t.Fatalf("pending answer carries %+v", st)
	}
	for _, p := range []struct {
		id   shared.ID
		code string
	}{{id, s.resp.UserCode}, {otherID, other.resp.UserCode}} {
		if _, err := f.approveP(ctx, a, p.id, approve(a, p.code)); err != nil {
			t.Fatalf("approve: %v", err)
		}
	}

	st := f.status(s)
	g, err := pairing.VerifyGrant(st.Grant, s.platformPub, s.pub(), s.resp.PairingID, s.nonce)
	if err != nil {
		t.Fatalf("the approval answer's grant does not verify: %v", err)
	}
	if g.Identity.SensorID != st.Identity.SensorID || g.Identity.TenantID != a.TenantID.String() || g.Identity.KeyID != s.thumb() {
		t.Fatalf("grant identity %+v, answer identity %+v", g.Identity, st.Identity)
	}
	if g.SignedJobs == nil || len(g.SignedJobs.Keys) != 1 || g.SignedJobs.Keys[0].KeyID != jobs.Keys[0].KeyID ||
		!bytes.Equal(g.SignedJobs.KeySet, keyset) || len(g.TLSAnchors) != 1 || g.TLSAnchors[0] != anchor {
		t.Fatalf("grant = %+v", g)
	}

	// Another sensor's grant, valid for it, is refused by this one (a
	// replay), and this grant is refused for another nonce.
	ost := f.status(other)
	if _, err := pairing.VerifyGrant(ost.Grant, s.platformPub, s.pub(), s.resp.PairingID, s.nonce); !errors.Is(err, pairing.ErrGrantBinding) {
		t.Fatalf("another sensor's grant: %v, want ErrGrantBinding", err)
	}
	if _, err := pairing.VerifyGrant(st.Grant, s.platformPub, s.pub(), s.resp.PairingID, other.nonce); !errors.Is(err, pairing.ErrGrantBinding) {
		t.Fatalf("another nonce: %v, want ErrGrantBinding", err)
	}

	done, err := f.confirm(s, &g.Identity)
	if err != nil || done.Status != pairing.StatusCompleted {
		t.Fatalf("confirm: %v %+v", err, done)
	}
	cg, err := pairing.VerifyGrant(done.Grant, s.platformPub, s.pub(), s.resp.PairingID, s.nonce)
	if err != nil || cg.Identity.SensorID != g.Identity.SensorID || cg.Identity.TenantID != g.Identity.TenantID {
		t.Fatalf("the confirm answer's grant: %v %+v", err, cg)
	}
}

// Without a job signer or TLS roots the grant states neither, so a sensor
// pins nothing it was not given.
func TestPairing_GrantWithoutSignerOrAnchors_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-grant-plain")
	s := newSensor(1)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	if _, err := f.approveP(ctx, a, id, approve(a, s.resp.UserCode)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	g, err := pairing.VerifyGrant(f.status(s).Grant, s.platformPub, s.pub(), s.resp.PairingID, s.nonce)
	if err != nil || g.SignedJobs != nil || len(g.TLSAnchors) != 0 {
		t.Fatalf("grant: %v %+v", err, g)
	}
}
