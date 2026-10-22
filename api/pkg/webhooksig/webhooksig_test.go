package webhooksig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Independent reference computation, written from the format description
// and not from Sign, so a mistake in Sign cannot hide behind itself.
func referenceSig(secret, id, ts, body string) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id + "." + ts + "." + body))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func TestHeaders_MatchReferenceAndVerify(t *testing.T) {
	secret := "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	ts := time.Unix(1614265330, 0)
	body := []byte(`{"test": 2432232314}`)
	h, err := Headers("msg_p5jXN8AQM9LWM0D4loKWxJek", ts, body, secret)
	if err != nil {
		t.Fatal(err)
	}
	want := "v1," + referenceSig(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", string(body))
	if h[HeaderSignature] != want {
		t.Fatalf("signature %q, want %q", h[HeaderSignature], want)
	}
	// The published Standard Webhooks test vector for these inputs.
	if h[HeaderSignature] != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature %q does not match the specification's test vector", h[HeaderSignature])
	}
	if h[HeaderTimestamp] != "1614265330" || h[HeaderID] != "msg_p5jXN8AQM9LWM0D4loKWxJek" {
		t.Fatalf("headers %+v", h)
	}
	hdr := http.Header{}
	for k, v := range h {
		hdr.Set(k, v)
	}
	if err := Verify(secret, hdr.Get, body, ts.Add(time.Minute), DefaultTolerance); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerify_Refusals(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := GenerateSecret()
	now := time.Now()
	body := []byte(`{"event_type":"new_finding"}`)
	h, _ := Headers("outbox-1", now, body, secret)
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if err := Verify(other, get(h), body, now, DefaultTolerance); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := Verify(secret, get(h), []byte(`{"event_type":"x"}`), now, DefaultTolerance); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("tampered body: %v", err)
	}
	// Replay outside the window.
	if err := Verify(secret, get(h), body, now.Add(6*time.Minute), DefaultTolerance); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("replay: %v", err)
	}
	// A changed id or timestamp breaks the signature: both are signed.
	moved := map[string]string{HeaderID: "outbox-2", HeaderTimestamp: h[HeaderTimestamp], HeaderSignature: h[HeaderSignature]}
	if err := Verify(secret, get(moved), body, now, DefaultTolerance); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("changed id: %v", err)
	}
	if err := Verify(secret, get(map[string]string{}), body, now, DefaultTolerance); !errors.Is(err, ErrHeaders) {
		t.Fatalf("no headers: %v", err)
	}
	if _, err := ParseSecret("not-a-secret"); !errors.Is(err, ErrSecret) {
		t.Fatalf("parse: %v", err)
	}
}

// During a rotation overlap both secrets verify.
func TestHeaders_TwoSecretsDuringOverlap(t *testing.T) {
	cur, _ := GenerateSecret()
	prev, _ := GenerateSecret()
	now := time.Now()
	body := []byte(`{}`)
	h, err := Headers("outbox-9", now, body, cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(h[HeaderSignature])); n != 2 {
		t.Fatalf("%d signatures, want 2", n)
	}
	get := func(k string) string { return h[k] }
	for name, s := range map[string]string{"current": cur, "previous": prev} {
		if err := Verify(s, get, body, now, DefaultTolerance); err != nil {
			t.Fatalf("%s secret: %v", name, err)
		}
	}
}

func TestGenerateSecret_Shape(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseSecret(s)
	if err != nil || len(key) != 32 {
		t.Fatalf("secret %q key len %d err %v", s, len(key), err)
	}
}
