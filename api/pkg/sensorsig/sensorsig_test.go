package sensorsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T, now time.Time) *Signer {
	t.Helper()
	s, err := NewSigner(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return now }
	return s
}

func signed(t *testing.T, s *Signer, method, url, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if err := s.Sign(r, []byte(body)); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1790000000, 0)
	s := testSigner(t, now)
	for _, body := range []string{"", `{"a":1}`} {
		r := signed(t, s, http.MethodPost, "https://p.example/api/v2/sensor/heartbeat?x=1", body)
		p, err := Parse(r.Header)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.CheckWindow(now); err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(r, s.PublicKey()); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			if err := VerifyContentDigest(r.Header.Get(HeaderContentDigest), []byte(body)); err != nil {
				t.Fatal(err)
			}
			if err := VerifyContentDigest(r.Header.Get(HeaderContentDigest), []byte(body+" ")); !errors.Is(err, ErrDigest) {
				t.Fatalf("changed body: %v", err)
			}
		}
	}
}

func TestTamperingFails(t *testing.T) {
	now := time.Unix(1790000000, 0)
	s := testSigner(t, now)
	other := testSigner(t, now)
	other.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	cases := map[string]func(r *http.Request){
		"method": func(r *http.Request) { r.Method = http.MethodPut },
		"path":   func(r *http.Request) { r.URL.Path = "/api/v2/sensor/commands" },
		"query":  func(r *http.Request) { r.URL.RawQuery = "x=2" },
		"digest": func(r *http.Request) { r.Header.Set(HeaderContentDigest, ContentDigest([]byte("other"))) },
	}
	for name, mutate := range cases {
		r := signed(t, s, http.MethodPost, "https://p.example/api/v2/sensor/heartbeat?x=1", `{"a":1}`)
		mutate(r)
		p, err := Parse(r.Header)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(r, s.PublicKey()); err == nil {
			t.Fatalf("%s: tampered request verified", name)
		}
	}
	r := signed(t, s, http.MethodGet, "https://p.example/x", "")
	p, _ := Parse(r.Header)
	if err := p.Verify(r, other.PublicKey()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("other key: %v", err)
	}
}

func TestWindow(t *testing.T) {
	now := time.Unix(1790000000, 0)
	s := testSigner(t, now)
	r := signed(t, s, http.MethodGet, "https://p.example/x", "")
	p, _ := Parse(r.Header)
	if err := p.CheckWindow(now.Add(DefaultWindow + MaxClockSkew + time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("late: %v", err)
	}
	if err := p.CheckWindow(now.Add(-MaxClockSkew - time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("early: %v", err)
	}
}

func TestParseRefusesOutsideProfile(t *testing.T) {
	now := time.Unix(1790000000, 0)
	s := testSigner(t, now)
	good := signed(t, s, http.MethodGet, "https://p.example/x", "")
	in, sig := good.Header.Get(HeaderSignatureInput), good.Header.Get(HeaderSignature)
	cases := map[string][2]string{
		"no label":        {strings.TrimPrefix(in, "sig1="), sig},
		"other label":     {strings.Replace(in, "sig1=", "sig2=", 1), sig},
		"extra component": {strings.Replace(in, `"@query")`, `"@query" "@authority")`, 1), sig},
		"missing query":   {strings.Replace(in, ` "@query"`, "", 1), sig},
		"other alg":       {strings.Replace(in, `alg="ed25519"`, `alg="hmac-sha256"`, 1), sig},
		"other tag":       {strings.Replace(in, Tag, "x", 1), sig},
		"extra param":     {in + `;foo="bar"`, sig},
		"space":           {strings.Replace(in, ";created", "; created", 1), sig},
		"short sig":       {in, "sig1=:AAAA:"},
		"bad base64":      {in, "sig1=:!!!:"},
		"long window":     {strings.Replace(in, "expires=1790000120", "expires=1790009999", 1), sig},
	}
	for name, c := range cases {
		h := http.Header{}
		h.Set(HeaderSignatureInput, c[0])
		h.Set(HeaderSignature, c[1])
		p, err := Parse(h)
		if err == nil && name == "long window" {
			err = p.CheckWindow(now)
		}
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	h := http.Header{}
	if _, err := Parse(h); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing: %v", err)
	}
	h.Add(HeaderSignatureInput, in)
	h.Add(HeaderSignatureInput, in)
	h.Set(HeaderSignature, sig)
	if _, err := Parse(h); err == nil {
		t.Fatal("two inputs accepted")
	}
}

func TestTransportSignsAndDropsBearer(t *testing.T) {
	now := time.Now()
	s := testSigner(t, now)
	s.Now = time.Now
	var got *http.Request
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	c := &http.Client{Transport: &Transport{Signer: s}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/v2/sensor/heartbeat", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer octs_secret")
	req.Header.Set("X-API-Key", "octs_secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got.Header.Get("Authorization") != "" || got.Header.Get("X-API-Key") != "" {
		t.Fatal("bearer credential forwarded")
	}
	p, err := Parse(got.Header)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(got, s.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContentDigest(got.Header.Get(HeaderContentDigest), gotBody); err != nil {
		t.Fatal(err)
	}
}

func TestThumbprintRFC8037Example(t *testing.T) {
	// RFC 8037 Appendix A.3: the thumbprint of the A.1 public key.
	pub := []byte{0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}
	if got := Thumbprint(pub); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", got)
	}
}
