package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func ticketFor(t *testing.T, key ed25519.PrivateKey, mod func(*Ticket)) (string, Ticket) {
	t.Helper()
	sensorPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	tk := Ticket{V: 1, Realm: "realm-1", Tenant: "tenant-1", Sensor: "sensor-1", Key: sensorPub, Relay: "relay-1",
		IAT: now.Unix(), Exp: now.Add(time.Hour).Unix()}
	if mod != nil {
		mod(&tk)
	}
	s, err := SignTicket(key, tk)
	if err != nil {
		t.Fatal(err)
	}
	return s, tk
}

func TestTicketVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok, want := ticketFor(t, priv, nil)
	got, err := VerifyTicket(tok, []ed25519.PublicKey{pub}, "relay-1", time.Now())
	if err != nil || got.Sensor != want.Sensor || !got.KeyMatches(want.Key) {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if realm, ok := PeekRealm(tok); !ok || realm != "realm-1" {
		t.Fatalf("PeekRealm = %q %v", realm, ok)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if got.KeyMatches(other) {
		t.Fatal("another key matched")
	}
}

func TestTicketRefusals(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	keys := []ed25519.PublicKey{pub}
	forged, _ := ticketFor(t, otherPriv, nil)
	if _, err := VerifyTicket(forged, keys, "relay-1", now); !errors.Is(err, ErrTicket) {
		t.Errorf("forged: %v", err)
	}
	good, _ := ticketFor(t, priv, nil)
	if _, err := VerifyTicket(good, keys, "relay-2", now); !errors.Is(err, ErrTicket) {
		t.Errorf("other relay: %v", err)
	}
	if _, err := VerifyTicket(good, keys, "relay-1", now.Add(2*time.Hour)); !errors.Is(err, ErrTicketExpiry) {
		t.Errorf("expired: %v", err)
	}
	if _, err := VerifyTicket(good, keys, "relay-1", now.Add(-time.Hour)); !errors.Is(err, ErrTicketExpiry) {
		t.Errorf("not yet valid: %v", err)
	}
	// Payload changed after signing.
	parts := strings.Split(strings.TrimPrefix(good, "v1."), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[0])
	evil := bytes.Replace(payload, []byte("sensor-1"), []byte("sensor-2"), 1)
	tampered := "v1." + base64.RawURLEncoding.EncodeToString(evil) + "." + parts[1]
	if _, err := VerifyTicket(tampered, keys, "relay-1", now); !errors.Is(err, ErrTicket) {
		t.Errorf("tampered: %v", err)
	}
	for _, bad := range []string{"", "v2.a.b", "v1.", "v1.!!.!!", strings.Repeat("a", MaxTicketBytes+1)} {
		if _, err := VerifyTicket(bad, keys, "relay-1", now); err == nil {
			t.Errorf("accepted %q", bad[:min(len(bad), 20)])
		}
	}
	// Signing refuses bad tickets.
	for name, mod := range map[string]func(*Ticket){
		"ttl over 24h":  func(tk *Ticket) { tk.Exp = tk.IAT + int64((25*time.Hour)/time.Second) },
		"bad sensor id": func(tk *Ticket) { tk.Sensor = "../x" },
		"short key":     func(tk *Ticket) { tk.Key = []byte("k") },
		"version":       func(tk *Ticket) { tk.V = 2 },
	} {
		sensorPub, _, _ := ed25519.GenerateKey(nil)
		tk := Ticket{V: 1, Realm: "r", Tenant: "t", Sensor: "s", Key: sensorPub, Relay: "relay-1", IAT: now.Unix(), Exp: now.Add(time.Hour).Unix()}
		mod(&tk)
		if _, err := SignTicket(priv, tk); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestBatchRoundTrip(t *testing.T) {
	items := []Item{{Sensor: "sensor-1", Envelope: []byte("aaa")}, {Sensor: "", Envelope: bytes.Repeat([]byte{1}, 1000)}}
	var buf bytes.Buffer
	if err := WriteBatch(&buf, items); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBatch(bytes.NewReader(buf.Bytes()), 10, 1<<20)
	if err != nil || len(got) != 2 || got[0].Sensor != "sensor-1" || len(got[1].Envelope) != 1000 {
		t.Fatalf("read: %+v %v", got, err)
	}
	if _, err := ReadBatch(bytes.NewReader(buf.Bytes()), 1, 1<<20); !errors.Is(err, ErrFrame) {
		t.Fatalf("item cap: %v", err)
	}
	if _, err := ReadBatch(bytes.NewReader(buf.Bytes()), 10, 500); !errors.Is(err, ErrFrame) {
		t.Fatalf("byte cap: %v", err)
	}
	if _, err := ReadBatch(bytes.NewReader(buf.Bytes()[:buf.Len()-1]), 10, 1<<20); !errors.Is(err, ErrFrame) {
		t.Fatalf("truncated: %v", err)
	}
	var bad bytes.Buffer
	_ = WriteBatch(&bad, []Item{{Sensor: "ok", Envelope: []byte("x")}})
	b := bad.Bytes()
	copy(b[2:4], "..")
	if _, err := ReadBatch(bytes.NewReader(b), 10, 1<<20); !errors.Is(err, ErrFrame) {
		t.Fatalf("bad sensor id: %v", err)
	}
	if err := WriteBatch(&bytes.Buffer{}, []Item{{Envelope: nil}}); !errors.Is(err, ErrFrame) {
		t.Fatalf("empty envelope written: %v", err)
	}
}

func FuzzReadBatch(f *testing.F) {
	var buf bytes.Buffer
	_ = WriteBatch(&buf, []Item{{Sensor: "s", Envelope: []byte("e")}})
	f.Add(buf.Bytes())
	f.Add([]byte{0, 0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		items, err := ReadBatch(bytes.NewReader(b), 16, 1<<20)
		if err == nil && len(items) > 16 {
			t.Fatal("item cap ignored")
		}
	})
}

func FuzzVerifyTicket(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sensorPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	good, _ := SignTicket(priv, Ticket{V: 1, Realm: "r", Tenant: "t", Sensor: "s", Key: sensorPub, Relay: "relay-1", IAT: now.Unix(), Exp: now.Add(time.Hour).Unix()})
	f.Add(good)
	f.Add("v1.e30.AA")
	f.Fuzz(func(t *testing.T, tok string) {
		if _, err := VerifyTicket(tok, []ed25519.PublicKey{pub}, "relay-1", now); err == nil && tok != good {
			t.Fatal("forged ticket accepted")
		}
		_, _ = PeekRealm(tok)
	})
}

// TestBatchVector pins the wire framing against the file shared with the
// sdk-go copy of this package; both sides keep testdata/vector-batch-v1.json
// byte-identical.
func TestBatchVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vector-batch-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Items []struct {
			Sensor      string `json:"sensor"`
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"items"`
		FramedHex string            `json:"framed_hex"`
		Invalid   map[string]string `json:"invalid_frames_hex"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var items []Item
	for _, it := range v.Items {
		env, err := hex.DecodeString(it.EnvelopeHex)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, Item{Sensor: it.Sensor, Envelope: env})
	}
	var buf bytes.Buffer
	if err := WriteBatch(&buf, items); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != v.FramedHex {
		t.Fatalf("framing drifted from the vector:\n got %s\nwant %s", got, v.FramedHex)
	}
	framed, _ := hex.DecodeString(v.FramedHex)
	got, err := ReadBatch(bytes.NewReader(framed), 10, 1<<20)
	if err != nil || len(got) != len(items) {
		t.Fatalf("read vector: %v %v", got, err)
	}
	for i := range items {
		if got[i].Sensor != items[i].Sensor || !bytes.Equal(got[i].Envelope, items[i].Envelope) {
			t.Fatalf("item %d differs: %+v", i, got[i])
		}
	}
	for name, h := range v.Invalid {
		b, _ := hex.DecodeString(h)
		if _, err := ReadBatch(bytes.NewReader(b), 10, 1<<20); !errors.Is(err, ErrFrame) {
			t.Errorf("invalid frame %s accepted: %v", name, err)
		}
	}
}
