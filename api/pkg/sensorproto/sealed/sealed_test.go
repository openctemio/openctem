package sealed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

type parties struct {
	sensorKey, ingestKey *PrivateKey
	respPub              ed25519.PublicKey
	respPriv             ed25519.PrivateKey
	route                Route
}

func newParties(t *testing.T) parties {
	t.Helper()
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ik, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	return parties{sensorKey: sk, ingestKey: ik, respPub: pub, respPriv: priv, route: Route{Realm: "realm-1", SensorID: "sensor-1"}}
}

func sampleRequest(p parties) *Request {
	return &Request{RequestMeta: RequestMeta{Method: "POST", Path: "/api/v2/sensor/heartbeat?x=1", ReplyKey: p.sensorKey.Public().Bytes(),
		Header: http.Header{"Signature": {"sig1=:abc:"}, "Signature-Input": {`sig1=("@method")`}, "Content-Type": {"application/json"},
			"Connection": {"close"}, "Host": {"relay.example"}}}, Body: []byte(`{"status":"secret-findings"}`)}
}

func TestRequestRoundTrip(t *testing.T) {
	p := newParties(t)
	req := sampleRequest(p)
	env, err := SealRequest(p.ingestKey.Public(), p.route, req)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, []byte("secret-findings")) || bytes.Contains(env, []byte("heartbeat")) {
		t.Fatal("plaintext visible in the envelope")
	}
	got, err := OpenRequest([]*PrivateKey{p.ingestKey}, p.route, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" || got.Path != "/api/v2/sensor/heartbeat?x=1" || string(got.Body) != `{"status":"secret-findings"}` ||
		got.Header.Get("Signature") != "sig1=:abc:" || got.ID == "" {
		t.Fatalf("request %+v", got)
	}
	if rt, err := got.ReplyTo(); err != nil || rt.KeyID() != p.sensorKey.KeyID() {
		t.Fatalf("reply key: %v", err)
	}
	if got.Header.Get("Connection") != "" || got.Header.Get("Host") != "" {
		t.Fatal("connection-level headers carried")
	}
}

func TestRequestRefusals(t *testing.T) {
	p := newParties(t)
	env, err := SealRequest(p.ingestKey.Public(), p.route, sampleRequest(p))
	if err != nil {
		t.Fatal(err)
	}
	// Every single-byte change after the magic is refused.
	for i := 4; i < len(env); i += 97 {
		bad := append([]byte(nil), env...)
		bad[i] ^= 0x40
		if _, err := OpenRequest([]*PrivateKey{p.ingestKey}, p.route, bad); err == nil {
			t.Fatalf("byte %d altered and still opened", i)
		}
	}
	// Moved to another sensor's or realm's mailbox.
	for _, r := range []Route{{Realm: "realm-1", SensorID: "sensor-2"}, {Realm: "realm-2", SensorID: "sensor-1"}} {
		if _, err := OpenRequest([]*PrivateKey{p.ingestKey}, r, env); !errors.Is(err, ErrOpen) {
			t.Fatalf("route %+v: %v", r, err)
		}
	}
	// Not our key.
	other, _ := GenerateKey()
	if _, err := OpenRequest([]*PrivateKey{other}, p.route, env); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("other key: %v", err)
	}
	// A response envelope is not a request.
	resp, _ := SealResponse(p.ingestKey.Public(), p.respPriv, p.route, Digest(env), &Response{Status: 200})
	if _, err := OpenRequest([]*PrivateKey{p.ingestKey}, p.route, resp); !errors.Is(err, ErrMalformed) {
		t.Fatalf("response as request: %v", err)
	}
	// Truncated.
	if _, err := OpenRequest([]*PrivateKey{p.ingestKey}, p.route, env[:30]); err == nil {
		t.Fatal("truncated envelope opened")
	}
}

func TestKeyRotation(t *testing.T) {
	p := newParties(t)
	next, _ := GenerateKey()
	envOld, _ := SealRequest(p.ingestKey.Public(), p.route, sampleRequest(p))
	envNew, _ := SealRequest(next.Public(), p.route, sampleRequest(p))
	keys := []*PrivateKey{p.ingestKey, next}
	for _, e := range [][]byte{envOld, envNew} {
		if _, err := OpenRequest(keys, p.route, e); err != nil {
			t.Fatalf("rotation: %v", err)
		}
	}
	h, err := PeekHeader(envNew)
	if err != nil || h.KeyID != next.KeyID() || h.Kind != KindRequest {
		t.Fatalf("header %+v %v", h, err)
	}
}

func TestResponseBinding(t *testing.T) {
	p := newParties(t)
	reqEnv, _ := SealRequest(p.ingestKey.Public(), p.route, sampleRequest(p))
	d := Digest(reqEnv)
	now := time.Now()
	resp := &Response{Status: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"jobs":["secret-job"]}`)}
	env, err := SealResponse(p.sensorKey.Public(), p.respPriv, p.route, d, resp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, []byte("secret-job")) {
		t.Fatal("plaintext visible in the response envelope")
	}
	got, err := OpenResponse(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, d, env, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != 200 || string(got.Body) != `{"jobs":["secret-job"]}` {
		t.Fatalf("response %+v", got)
	}

	// With several requests outstanding, the sensor learns which one a
	// response answers.
	if _, gotD, err := OpenResponseAny(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, env, now); err != nil || gotD != d {
		t.Fatalf("OpenResponseAny: %x %v", gotD, err)
	}

	// The relay swaps the response onto another request.
	other, _ := SealRequest(p.ingestKey.Public(), p.route, sampleRequest(p))
	if _, err := OpenResponse(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, Digest(other), env, now); !errors.Is(err, ErrBinding) {
		t.Fatalf("swapped response: %v", err)
	}
	// The relay forges a response (it knows the sensor's public key, not
	// the platform's response key).
	_, relayKey, _ := ed25519.GenerateKey(nil)
	forged, _ := SealResponse(p.sensorKey.Public(), relayKey, p.route, d, &Response{Status: 200, Body: []byte(`{"jobs":["evil"]}`)})
	if _, err := OpenResponse(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, d, forged, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged response: %v", err)
	}
	// A response to another sensor (sealed to this sensor's key, signed by
	// the platform, but naming the other sensor) does not answer here.
	otherRoute := Route{Realm: "realm-1", SensorID: "sensor-2"}
	misrouted, _ := SealResponse(p.sensorKey.Public(), p.respPriv, otherRoute, d, resp)
	if _, err := OpenResponse(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, d, misrouted, now); err == nil {
		t.Fatal("response for another sensor opened")
	}
	// Too old (replayed much later).
	if _, err := OpenResponse(p.sensorKey, []ed25519.PublicKey{p.respPub}, p.route, d, env, now.Add(time.Hour)); !errors.Is(err, ErrBinding) {
		t.Fatalf("stale response: %v", err)
	}
	// No pinned key.
	if _, err := OpenResponse(p.sensorKey, nil, p.route, d, env, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("no pinned key: %v", err)
	}
}

func TestHeaderInjectionAndLimits(t *testing.T) {
	p := newParties(t)
	rk := p.sensorKey.Public().Bytes()
	for _, req := range []*Request{
		{RequestMeta: RequestMeta{Method: "GET", Path: "/x", ReplyKey: rk, Header: http.Header{"X-A": {"a\r\nX-Evil: 1"}}}},
		{RequestMeta: RequestMeta{Method: "GET", Path: "no-slash", ReplyKey: rk}},
		{RequestMeta: RequestMeta{Method: "GET /x HTTP/1.1", Path: "/x", ReplyKey: rk}},
		{RequestMeta: RequestMeta{Method: "GET", Path: "/x y", ReplyKey: rk}},
		{RequestMeta: RequestMeta{Method: "GET", Path: "/x", ReplyKey: rk}, Body: make([]byte, MaxBody+1)},
		{RequestMeta: RequestMeta{Method: "GET", Path: "/x"}},
		{RequestMeta: RequestMeta{Method: "GET", Path: "/x", ReplyKey: []byte("short")}},
	} {
		if _, err := SealRequest(p.ingestKey.Public(), p.route, req); !errors.Is(err, ErrMalformed) {
			t.Errorf("accepted %+v: %v", req.RequestMeta, err)
		}
	}
	many := http.Header{}
	for i := range MaxHeaders + 1 {
		many.Add("X-H", string(rune('a'+i%26)))
	}
	if _, err := SealRequest(p.ingestKey.Public(), p.route, &Request{RequestMeta: RequestMeta{Method: "GET", Path: "/", Header: many, ReplyKey: rk}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("too many headers: %v", err)
	}
	if _, err := SealRequest(p.ingestKey.Public(), Route{}, sampleRequest(p)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty route: %v", err)
	}
}

func TestKeySerialization(t *testing.T) {
	k, _ := GenerateKey()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivateKey(b)
	if err != nil || k2.KeyID() != k.KeyID() {
		t.Fatalf("private key round trip: %v", err)
	}
	pub, err := ParsePublicKey(k.Public().Bytes())
	if err != nil || pub.KeyID() != k.KeyID() {
		t.Fatalf("public key round trip: %v", err)
	}
	if _, err := ParsePublicKey([]byte("short")); err == nil {
		t.Fatal("short public key accepted")
	}
}

// vector is sdk-go's test vector (pkg/sealedmsg/testdata/vector-v1.json,
// copied unchanged): this implementation must open the sensor's request
// with the ingest key and the platform's response with the sensor key.
type vector struct {
	Realm       string `json:"realm"`
	SensorID    string `json:"sensor_id"`
	IngestKey   string `json:"ingest_private_key"`
	SensorKey   string `json:"sensor_private_key"`
	ResponsePub string `json:"response_public_key"`
	Request     string `json:"request_envelope"`
	Response    string `json:"response_envelope"`
	IssuedAt    string `json:"issued_at"`
	WantPath    string `json:"want_path"`
	WantBody    string `json:"want_request_body"`
	WantResp    string `json:"want_response_body"`
}

func TestVector(t *testing.T) {
	const path = "testdata/vector-v1.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	ik, err := ParsePrivateKey(dec(v.IngestKey))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ParsePrivateKey(dec(v.SensorKey))
	if err != nil {
		t.Fatal(err)
	}
	route := Route{Realm: v.Realm, SensorID: v.SensorID}
	req, err := OpenRequest([]*PrivateKey{ik}, route, dec(v.Request))
	if err != nil || req.Path != v.WantPath || string(req.Body) != v.WantBody {
		t.Fatalf("vector request: %+v %v", req, err)
	}
	issued, _ := time.Parse(time.RFC3339, v.IssuedAt)
	resp, err := OpenResponse(sk, []ed25519.PublicKey{dec(v.ResponsePub)}, route, Digest(dec(v.Request)), dec(v.Response), issued)
	if err != nil || string(resp.Body) != v.WantResp {
		t.Fatalf("vector response: %+v %v", resp, err)
	}
}
