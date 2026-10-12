package pairing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// The vectors are shared with sdk-go (sdk-go/pkg/sensorproto/pairing/
// testdata/vectors.json, byte-identical; sdk-go is where they are
// regenerated with -update). A change here without the same change there
// breaks pairing between the sensor and the platform.
var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

type sasVector struct {
	SensorSeed    string `json:"sensor_seed_hex"`
	PlatformSeed  string `json:"platform_seed_hex"`
	SensorPub     string `json:"sensor_public_key"`
	PlatformPub   string `json:"platform_public_key"`
	SensorThumb   string `json:"sensor_thumbprint"`
	PlatformThumb string `json:"platform_thumbprint"`
	SensorNonce   string `json:"sensor_nonce"`
	PlatformNonce string `json:"platform_nonce"`
	Commitment    string `json:"commitment"`
	SAS           string `json:"sas"`
	PairingID     string `json:"pairing_id"`
	ExpiresUnix   int64  `json:"expires_unix"`
	PlatformSig   string `json:"platform_signature"`
	TenantID      string `json:"tenant_id"`
	SensorID      string `json:"sensor_id"`
	ConfirmSig    string `json:"confirm_signature"`
}

type codeVector struct {
	BytesHex string `json:"bytes_hex"`
	Code     string `json:"code"`
}

type normVector struct {
	Typed string `json:"typed"`
	Code  string `json:"code"`
}

type sigVector struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Body           string `json:"body"`
	Created        int64  `json:"created"`
	Nonce          string `json:"nonce"`
	ContentDigest  string `json:"content_digest"`
	SignatureInput string `json:"signature_input"`
	SignatureBase  string `json:"signature_base"`
	Signature      string `json:"signature"`
}

type vectors struct {
	WordsDigest string       `json:"words_digest"`
	SAS         []sasVector  `json:"sas"`
	Codes       []codeVector `json:"codes"`
	Normalize   []normVector `json:"normalize"`
	Signatures  []sigVector  `json:"signatures"`
}

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

func build(t *testing.T) vectors {
	t.Helper()
	v := vectors{WordsDigest: pairing.WordsDigest()}
	for i, c := range []struct {
		s, p, sn, pn byte
	}{{1, 2, 3, 4}, {0x11, 0x22, 0x33, 0x44}, {0xa0, 0xb0, 0xc0, 0xd0}} {
		sk := ed25519.NewKeyFromSeed(seed(c.s))
		pk := ed25519.NewKeyFromSeed(seed(c.p))
		spub, ppub := sk.Public().(ed25519.PublicKey), pk.Public().(ed25519.PublicKey)
		sn, pn := bytes.Repeat([]byte{c.sn}, 32), bytes.Repeat([]byte{c.pn}, 32)
		commit := pairing.Commit(sn)
		id := []string{"0b5a3c1e-6f0f-4d4c-9a51-0e1c2b3a4d5e", "5f1d6a8e-1b2c-4d3e-8f90-a1b2c3d4e5f6", "9c8b7a65-4321-4fed-b0a9-876543210fed"}[i]
		exp := time.Unix(1790000000+int64(i), 0)
		psig := ed25519.Sign(pk, pairing.PlatformTranscript(id, spub, commit, ppub, pn, exp))
		tenant, sensor := "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-aaaaaaaaaaaa"
		csig := ed25519.Sign(sk, pairing.ConfirmTranscript(id, sensor, tenant, sensorsig.Thumbprint(spub)))
		v.SAS = append(v.SAS, sasVector{
			SensorSeed: hex.EncodeToString(seed(c.s)), PlatformSeed: hex.EncodeToString(seed(c.p)),
			SensorPub: pairing.Encode(spub), PlatformPub: pairing.Encode(ppub),
			SensorThumb: sensorsig.Thumbprint(spub), PlatformThumb: sensorsig.Thumbprint(ppub),
			SensorNonce: pairing.Encode(sn), PlatformNonce: pairing.Encode(pn), Commitment: pairing.Encode(commit),
			SAS: pairing.ComputeSAS(spub, ppub, sn, pn).String(), PairingID: id, ExpiresUnix: exp.Unix(),
			PlatformSig: pairing.Encode(psig), TenantID: tenant, SensorID: sensor, ConfirmSig: pairing.Encode(csig),
		})
	}
	for _, h := range []string{"0000000000", "ffffffffff", "0123456789", "deadbeef42"} {
		b, _ := hex.DecodeString(h)
		code := pairing.EncodeCodeForTest([5]byte(b))
		v.Codes = append(v.Codes, codeVector{BytesHex: h, Code: code})
	}
	for _, typed := range []string{"k7qm-4ztd", "K7QM 4ZTD", "o1il-0000", "ABCD-EFGU", "ABC", "ABCDEFGHJ"} {
		code, err := pairing.NormalizeCode(typed)
		if err != nil {
			code = ""
		}
		v.Normalize = append(v.Normalize, normVector{Typed: typed, Code: code})
	}
	key := ed25519.NewKeyFromSeed(seed(1))
	for _, c := range []struct{ method, url, body string }{
		{"POST", "https://platform.example/api/v2/sensor/heartbeat", `{"status":"ok"}`},
		{"GET", "https://platform.example/api/v2/sensor/commands?limit=5&claim=1", ""},
		{"POST", "https://platform.example/api/v2/sensor/pairings", `{"protocol":"openctem-pairing/v1"}`},
	} {
		s, err := sensorsig.NewSigner(key)
		if err != nil {
			t.Fatal(err)
		}
		created := time.Unix(1790000000, 0)
		s.Now = func() time.Time { return created }
		s.Nonce = func() (string, error) { return "bm9uY2Utbm9uY2Utbm9uY2Ut", nil }
		r, _ := http.NewRequestWithContext(context.Background(), c.method, c.url, strings.NewReader(c.body))
		if err := s.Sign(r, []byte(c.body)); err != nil {
			t.Fatal(err)
		}
		p, err := sensorsig.Parse(r.Header)
		if err != nil {
			t.Fatal(err)
		}
		v.Signatures = append(v.Signatures, sigVector{
			Method: c.method, URL: c.url, Body: c.body, Created: created.Unix(), Nonce: "bm9uY2Utbm9uY2Utbm9uY2Ut",
			ContentDigest: r.Header.Get(sensorsig.HeaderContentDigest), SignatureInput: r.Header.Get(sensorsig.HeaderSignatureInput),
			SignatureBase: sensorsig.SignatureBase(sensorsig.ComponentsOf(r), p.Params), Signature: r.Header.Get(sensorsig.HeaderSignature),
		})
	}
	return v
}

func TestVectors(t *testing.T) {
	got := build(t)
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	const file = "testdata/vectors.json"
	if *update {
		if err := os.WriteFile(file, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, raw) {
		t.Fatalf("implementation no longer matches %s (protocol change?); diff the output of -update", file)
	}
}

func TestVectorsVerify(t *testing.T) {
	v := build(t)
	for _, c := range v.SAS {
		spub, _ := pairing.DecodeKey(c.SensorPub)
		commit, _ := pairing.DecodeFixed(c.Commitment, 32)
		sn, _ := pairing.DecodeFixed(c.SensorNonce, 32)
		if err := pairing.CheckCommitment(commit, sn); err != nil {
			t.Fatal(err)
		}
		resp := &pairing.StartResponse{PairingID: c.PairingID, PlatformKey: c.PlatformPub, PlatformNonce: c.PlatformNonce,
			PlatformSignature: c.PlatformSig, ExpiresAt: time.Unix(c.ExpiresUnix, 0)}
		if _, _, err := pairing.VerifyStart(resp, spub, commit, c.PlatformThumb, sensorsig.Thumbprint); err != nil {
			t.Fatalf("verify start: %v", err)
		}
		if _, _, err := pairing.VerifyStart(resp, spub, commit, "SHA256:"+c.SensorThumb, sensorsig.Thumbprint); err == nil {
			t.Fatal("a pin to another key must fail")
		}
		bad := *resp
		bad.PairingID = "other"
		if _, _, err := pairing.VerifyStart(&bad, spub, commit, "", sensorsig.Thumbprint); err == nil {
			t.Fatal("a changed transcript must fail")
		}
		wrong := bytes.Repeat([]byte{9}, 32)
		if err := pairing.CheckCommitment(commit, wrong); err == nil {
			t.Fatal("a different nonce must not open the commitment")
		}
	}
}

func TestSASChangesWithEveryInput(t *testing.T) {
	a, b, c, d := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	base := pairing.ComputeSAS(a, b, c, d)
	x := bytes.Repeat([]byte{5}, 32)
	for i, s := range []pairing.SAS{pairing.ComputeSAS(x, b, c, d), pairing.ComputeSAS(a, x, c, d), pairing.ComputeSAS(a, b, x, d), pairing.ComputeSAS(a, b, c, x)} {
		if s == base {
			t.Fatalf("input %d does not change the SAS", i)
		}
	}
	if !strings.Contains(base.String(), " · ") || len(base.Number) != 3 {
		t.Fatalf("SAS rendering %q", base.String())
	}
}

func TestWordList(t *testing.T) {
	seen := map[string]bool{}
	for i, w := range pairing.Words {
		if w == "" || len(w) > 8 || strings.ToLower(w) != w || seen[w] {
			t.Fatalf("word %d %q", i, w)
		}
		if i > 0 && pairing.Words[i-1] >= w {
			t.Fatalf("list not sorted at %d", i)
		}
		seen[w] = true
	}
}

func TestCodes(t *testing.T) {
	for range 100 {
		c, err := pairing.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		n, err := pairing.NormalizeCode(strings.ToLower(pairing.FormatCode(c)))
		if err != nil || n != c {
			t.Fatalf("round trip %q -> %q, %v", c, n, err)
		}
	}
}
