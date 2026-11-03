package licensekey_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/licensekey"
	lkt "github.com/openctemio/openctem/api/pkg/licensekey/licensekeytest"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const installID = "7f3c2a10-1111-4222-8333-944455556666"

func signed(c licensekey.Claims) []byte { return lkt.File(now, c) }

func withClaims(mut func(*licensekey.Claims)) []byte {
	c := lkt.Claims(now)
	mut(&c)
	return signed(c)
}

// envelopeFields decodes an envelope into a generic map to tamper with it.
func envelopeFields(t *testing.T, env []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intp(i int) *int { return &i }

func TestVerifyValid(t *testing.T) {
	file := signed(lkt.Claims(now))
	lic, err := lkt.Verifier().Verify(file, licensekey.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if lic.ID != "lic_TEST0001" || lic.KeySet.Version != 1 || !bytes.Equal(lic.File, file) {
		t.Fatalf("unexpected license %+v", lic.Claims)
	}
	if lic.KeyID == "" || !lic.Grants(limits.GrantAIWorker) || lic.StateAt(now) != licensekey.StateActive {
		t.Fatalf("key %q grants %v state %s", lic.KeyID, lic.Entitlements, lic.StateAt(now))
	}
}

func TestVerifyInputForms(t *testing.T) {
	file := signed(lkt.Claims(now))
	std := base64.StdEncoding.EncodeToString(file)
	wrapped := ""
	for i := 0; i < len(std); i += 76 {
		wrapped += std[i:min(i+76, len(std))] + "\n"
	}
	for name, in := range map[string]string{
		"json":            string(file),
		"json padded":     "\n  " + string(file) + "\n",
		"base64":          std,
		"base64 raw":      base64.RawStdEncoding.EncodeToString(file),
		"base64 wrapped":  wrapped,
		"base64 crlf/pad": " " + strings.ReplaceAll(wrapped, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			lic, err := lkt.Verifier().Verify([]byte(in), licensekey.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(lic.File, file) {
				t.Fatal("stored form differs from the JSON file")
			}
		})
	}
}

func TestVerifyRefusesMalformedAndOversized(t *testing.T) {
	file := signed(lkt.Claims(now))
	hugeB64 := base64.StdEncoding.EncodeToString(append([]byte("{"), bytes.Repeat([]byte(" "), licensekey.MaxFileBytes)...))
	var ks map[string]json.RawMessage
	_ = json.Unmarshal(file, &ks)
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, licensekey.ErrMalformed},
		{"whitespace", []byte(" \n\t"), licensekey.ErrMalformed},
		{"truncated", file[:len(file)/2], licensekey.ErrMalformed},
		{"truncated by one", file[:len(file)-1], licensekey.ErrMalformed},
		{"not base64", []byte("!!!not a license!!!"), licensekey.ErrMalformed},
		{"base64 of non-JSON", []byte(base64.StdEncoding.EncodeToString([]byte("hello world"))), licensekey.ErrMalformed},
		{"oversized input", bytes.Repeat([]byte("A"), 200<<10), licensekey.ErrTooLarge},
		{"oversized JSON", append(file[:len(file)-1], append(bytes.Repeat([]byte(" "), licensekey.MaxFileBytes), '}')...), licensekey.ErrTooLarge},
		{"oversized base64 content", []byte(hugeB64), licensekey.ErrTooLarge},
		{"unknown top-level key", []byte(`{"license":` + string(ks["license"]) + `,"keyset":` + string(ks["keyset"]) + `,"x":1}`), licensekey.ErrMalformed},
		{"missing keyset", []byte(`{"license":` + string(ks["license"]) + `}`), licensekey.ErrMalformed},
		{"duplicate top-level key", []byte(`{"license":` + string(ks["license"]) + `,"keyset":` + string(ks["keyset"]) + `,"keyset":` + string(ks["keyset"]) + `}`), licensekey.ErrMalformed},
		{"trailing data", append(append([]byte{}, file...), []byte(` {}`)...), licensekey.ErrMalformed},
		{"array", []byte(`[]`), licensekey.ErrMalformed},
		{"deep nesting", []byte(strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40)), licensekey.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lkt.Verifier().Verify(tc.in, licensekey.Options{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyRefusesTampering(t *testing.T) {
	c := lkt.Claims(now)
	ksEnv := lkt.DefaultKeySet(now).Sign()
	licEnv := lkt.Envelope(lkt.IssuingKey(0), licensekey.PayloadType, lkt.ClaimsPayload(c))

	// The payload is changed after signing (a longer term).
	tamperedPayload := func() []byte {
		m := envelopeFields(t, licEnv)
		c2 := c
		c2.ExpiresAt = c.ExpiresAt.Add(365 * 24 * time.Hour)
		m["payload"] = lkt.ClaimsPayload(c2)
		return mustJSON(t, m)
	}()
	tamperedKeySet := func() []byte {
		ks := lkt.DefaultKeySet(now)
		m := envelopeFields(t, ksEnv)
		ks.Keys = append(ks.Keys, lkt.Public(lkt.IssuingKey(9)))
		m["payload"] = ks.KeySetPayload()
		return mustJSON(t, m)
	}()
	flipSig := func(env []byte) []byte {
		m := envelopeFields(t, env)
		sigs := m["signatures"].([]any)
		s := sigs[0].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(s["sig"].(string))
		raw[0] ^= 0xff
		s["sig"] = base64.StdEncoding.EncodeToString(raw)
		return mustJSON(t, m)
	}
	relabel := func(env []byte, keyid string) []byte {
		m := envelopeFields(t, env)
		m["signatures"].([]any)[0].(map[string]any)["keyid"] = keyid
		return mustJSON(t, m)
	}
	manySigs := func(env []byte) []byte {
		m := envelopeFields(t, env)
		s := m["signatures"].([]any)
		m["signatures"] = []any{s[0], s[0], s[0], s[0], s[0]}
		return mustJSON(t, m)
	}
	unknownEnvField := func(env []byte) []byte {
		m := envelopeFields(t, env)
		m["extra"] = true
		return mustJSON(t, m)
	}
	wrongType := lkt.Envelope(lkt.IssuingKey(0), licensekey.KeySetPayloadType, lkt.ClaimsPayload(c))

	cases := []struct {
		name string
		file []byte
		want error
	}{
		{"tampered claims", lkt.Assemble(tamperedPayload, ksEnv), licensekey.ErrBadSignature},
		{"tampered key set", lkt.Assemble(licEnv, tamperedKeySet), licensekey.ErrBadSignature},
		{"license signature flipped", lkt.Assemble(flipSig(licEnv), ksEnv), licensekey.ErrBadSignature},
		{"key set signature flipped", lkt.Assemble(licEnv, flipSig(ksEnv)), licensekey.ErrBadSignature},
		{"license signed by a key outside the set",
			lkt.Assemble(lkt.Envelope(lkt.IssuingKey(1), licensekey.PayloadType, lkt.ClaimsPayload(c)), ksEnv), licensekey.ErrBadSignature},
		{"license signed by the root itself",
			lkt.Assemble(lkt.Envelope(lkt.Root(), licensekey.PayloadType, lkt.ClaimsPayload(c)), ksEnv), licensekey.ErrBadSignature},
		{"wrong key id on the license signature", lkt.Assemble(relabel(licEnv, "SHA256:00"), ksEnv), licensekey.ErrBadSignature},
		{"wrong key id on the key set signature", lkt.Assemble(licEnv, relabel(ksEnv, "SHA256:00")), licensekey.ErrBadSignature},
		{"too many signatures", lkt.Assemble(manySigs(licEnv), ksEnv), licensekey.ErrMalformed},
		{"unknown envelope field", lkt.Assemble(unknownEnvField(licEnv), ksEnv), licensekey.ErrMalformed},
		{"license payload type", lkt.Assemble(wrongType, ksEnv), licensekey.ErrMalformed},
		{"key set as license", lkt.Assemble(ksEnv, ksEnv), licensekey.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lkt.Verifier().Verify(tc.file, licensekey.Options{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyKeySetRules(t *testing.T) {
	c := lkt.Claims(now)
	licBy := func(k ed25519.PrivateKey, cl licensekey.Claims) []byte {
		return lkt.Envelope(k, licensekey.PayloadType, lkt.ClaimsPayload(cl))
	}
	ks := func(mut func(*lkt.KeySet)) []byte {
		k := lkt.DefaultKeySet(now)
		mut(&k)
		return k.Sign()
	}
	rawKeySet := func(mut func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(lkt.DefaultKeySet(now).KeySetPayload(), &m)
		mut(m)
		b, _ := json.Marshal(m)
		return lkt.Envelope(lkt.Root(), licensekey.KeySetPayloadType, b)
	}
	revokedC := c
	revokedC.ID = "lic_REVOKED1"
	nine := make([]ed25519.PublicKey, 9)
	for i := range nine {
		nine[i] = lkt.Public(lkt.IssuingKey(i + 10))
	}
	cases := []struct {
		name string
		file []byte
		opts licensekey.Options
		want error
	}{
		{"untrusted root", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Root = lkt.OtherRoot() })), licensekey.Options{}, licensekey.ErrUntrustedRoot},
		{"root public key not the trusted one", lkt.Assemble(licBy(lkt.IssuingKey(0), c), rawKeySet(func(m map[string]any) {
			m["root_public_key"] = base64.StdEncoding.EncodeToString(lkt.Public(lkt.OtherRoot()))
		})), licensekey.Options{}, licensekey.ErrUntrustedRoot},
		{"rolled back key set", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(*lkt.KeySet) {})), licensekey.Options{MinKeySetVersion: 2}, licensekey.ErrKeySetRollback},
		{"key set version 0", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Version = 0 })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set kind", lkt.Assemble(licBy(lkt.IssuingKey(0), c), rawKeySet(func(m map[string]any) { m["kind"] = "openctem.vulnfeed.keyset/v1" })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set unknown field", lkt.Assemble(licBy(lkt.IssuingKey(0), c), rawKeySet(func(m map[string]any) { m["extra"] = 1 })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set validity over 3 years", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.NotAfter = k.IssuedAt.Add(4 * 365 * 24 * time.Hour) })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set with no keys", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Keys = nil })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set with 9 keys", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Keys = nine })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set lists the root", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Keys = append(k.Keys, lkt.Public(lkt.Root())) })), licensekey.Options{}, licensekey.ErrMalformed},
		{"key set lists a key twice", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.Keys = append(k.Keys, k.Keys[0]) })), licensekey.Options{}, licensekey.ErrMalformed},
		{"license id revoked by its key set", lkt.Assemble(licBy(lkt.IssuingKey(0), revokedC), ks(func(k *lkt.KeySet) { k.Revoked.LicenseIDs = []string{"lic_REVOKED1"} })), licensekey.Options{}, licensekey.ErrRevoked},
		{"license id revoked by a newer key set seen before", lkt.Assemble(licBy(lkt.IssuingKey(0), revokedC), ks(func(*lkt.KeySet) {})), licensekey.Options{Revoked: licensekey.Revocations{LicenseIDs: []string{"lic_REVOKED1"}}}, licensekey.ErrRevoked},
		{"issuing key revoked by its key set", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) {
			k.Revoked.KeyIDs = []string{lkt.DefaultKeySetKeyID()}
		})), licensekey.Options{}, licensekey.ErrRevoked},
		{"issuing key revoked by a newer key set seen before", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(*lkt.KeySet) {})), licensekey.Options{Revoked: licensekey.Revocations{KeyIDs: []string{lkt.DefaultKeySetKeyID()}}}, licensekey.ErrRevoked},
		{"license expires after its key set", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.NotAfter = c.ExpiresAt.Add(-time.Hour) })), licensekey.Options{}, licensekey.ErrInvalidClaims},
		{"license issued before its key set", lkt.Assemble(licBy(lkt.IssuingKey(0), c), ks(func(k *lkt.KeySet) { k.IssuedAt = c.IssuedAt.Add(time.Hour) })), licensekey.Options{}, licensekey.ErrInvalidClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lkt.Verifier().Verify(tc.file, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Rotation: a newer key set lists new issuing keys and revokes the old one;
// the next root, once trusted, verifies key sets alone.
func TestVerifyRotation(t *testing.T) {
	c := lkt.Claims(now)
	v2 := lkt.DefaultKeySet(now)
	v2.Version = 2
	v2.Keys = []ed25519.PublicKey{lkt.Public(lkt.IssuingKey(1)), lkt.Public(lkt.IssuingKey(2))}
	v2.Revoked.KeyIDs = []string{lkt.DefaultKeySetKeyID()}
	file := lkt.Assemble(lkt.Envelope(lkt.IssuingKey(2), licensekey.PayloadType, lkt.ClaimsPayload(c)), v2.Sign())
	lic, err := lkt.Verifier().Verify(file, licensekey.Options{MinKeySetVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	if lic.KeySet.Version != 2 || len(lic.KeySet.Revoked.KeyIDs) != 1 {
		t.Fatalf("key set %+v", lic.KeySet)
	}
	// The old key's license, carrying the old key set, is refused once v2 was seen.
	old := signed(c)
	if _, err := lkt.Verifier().Verify(old, licensekey.Options{MinKeySetVersion: lic.KeySet.Version, Revoked: lic.KeySet.Revoked}); !errors.Is(err, licensekey.ErrKeySetRollback) {
		t.Fatalf("old key set after rotation: %v", err)
	}

	next := lkt.DefaultKeySet(now)
	next.Root = lkt.OtherRoot()
	nextFile := lkt.Assemble(lkt.Envelope(lkt.IssuingKey(0), licensekey.PayloadType, lkt.ClaimsPayload(c)), next.Sign())
	both := licensekey.NewVerifier(lkt.Public(lkt.Root()), lkt.Public(lkt.OtherRoot()))
	if _, err := both.Verify(nextFile, licensekey.Options{}); err != nil {
		t.Fatalf("next root: %v", err)
	}
	if _, err := lkt.Verifier().Verify(nextFile, licensekey.Options{}); !errors.Is(err, licensekey.ErrUntrustedRoot) {
		t.Fatalf("next root before it is trusted: %v", err)
	}
	if _, err := licensekey.NewVerifier().Verify(old, licensekey.Options{}); !errors.Is(err, licensekey.ErrNoTrustedRoot) {
		t.Fatalf("verifier without roots: %v", err)
	}
}

func TestVerifyClaims(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*licensekey.Claims)
		want error
	}{
		{"schema", func(c *licensekey.Claims) { c.Schema = "openctem.io/license/v2" }, licensekey.ErrInvalidClaims},
		{"id", func(c *licensekey.Claims) { c.ID = "x" }, licensekey.ErrInvalidClaims},
		{"customer id", func(c *licensekey.Claims) { c.CustomerID = "" }, licensekey.ErrInvalidClaims},
		{"type", func(c *licensekey.Claims) { c.Type = "unlimited" }, licensekey.ErrInvalidClaims},
		{"licensee empty", func(c *licensekey.Claims) { c.Licensee.Name = " " }, licensekey.ErrInvalidClaims},
		{"licensee e-mail", func(c *licensekey.Claims) { c.Licensee.Name = "jane@example.test" }, licensekey.ErrInvalidClaims},
		{"licensee control char", func(c *licensekey.Claims) { c.Licensee.Name = "Org\x1b[31m" }, licensekey.ErrInvalidClaims},
		{"licensee too long", func(c *licensekey.Claims) { c.Licensee.Name = strings.Repeat("a", 201) }, licensekey.ErrInvalidClaims},
		{"no not_before", func(c *licensekey.Claims) { c.NotBefore = time.Time{} }, licensekey.ErrInvalidClaims},
		{"expires before start", func(c *licensekey.Claims) { c.ExpiresAt = c.NotBefore }, licensekey.ErrInvalidClaims},
		{"term too long", func(c *licensekey.Claims) { c.ExpiresAt = c.NotBefore.Add(licensekey.MaxTerm + time.Hour) }, licensekey.ErrInvalidClaims},
		{"issued after expiry", func(c *licensekey.Claims) { c.IssuedAt = c.ExpiresAt.Add(time.Hour) }, licensekey.ErrInvalidClaims},
		{"grace missing", func(c *licensekey.Claims) { c.GraceDays = nil }, licensekey.ErrInvalidClaims},
		{"grace negative", func(c *licensekey.Claims) { c.GraceDays = intp(-1) }, licensekey.ErrInvalidClaims},
		{"grace too long", func(c *licensekey.Claims) { c.GraceDays = intp(licensekey.MaxGraceDays + 1) }, licensekey.ErrInvalidClaims},
		{"no entitlements", func(c *licensekey.Claims) { c.Entitlements = nil }, licensekey.ErrInvalidClaims},
		{"unknown entitlement", func(c *licensekey.Claims) { c.Entitlements = []limits.GrantKey{"unlimited_everything"} }, licensekey.ErrUnknownEntitlement},
		{"limit key is not a grant", func(c *licensekey.Claims) { c.Entitlements = []limits.GrantKey{"seats"} }, licensekey.ErrUnknownEntitlement},
		{"sso is never licensed", func(c *licensekey.Claims) { c.Entitlements = []limits.GrantKey{"sso.connections"} }, licensekey.ErrUnknownEntitlement},
		{"duplicate entitlement", func(c *licensekey.Claims) {
			c.Entitlements = []limits.GrantKey{limits.GrantAIWorker, limits.GrantAIWorker}
		}, licensekey.ErrInvalidClaims},
		{"meter name", func(c *licensekey.Claims) { c.Meters = map[string]int64{"Assets!": 1} }, licensekey.ErrInvalidClaims},
		{"meter negative", func(c *licensekey.Claims) { c.Meters = map[string]int64{"assets": -1} }, licensekey.ErrInvalidClaims},
		{"bind not a uuid", func(c *licensekey.Claims) { c.Bind = &licensekey.Binding{InstallationIDs: []string{"host-1"}} }, licensekey.ErrInvalidClaims},
		{"renewal over http", func(c *licensekey.Claims) { c.Renewal = &licensekey.Renewal{URL: "http://r.example.test/x"} }, licensekey.ErrInvalidClaims},
		{"renewal without url", func(c *licensekey.Claims) { c.Renewal = &licensekey.Renewal{} }, licensekey.ErrInvalidClaims},
		{"renewal user info", func(c *licensekey.Claims) { c.Renewal = &licensekey.Renewal{URL: "https://u:p@r.example.test/x"} }, licensekey.ErrInvalidClaims},
		{"renewal default", func(c *licensekey.Claims) {
			c.Renewal = &licensekey.Renewal{URL: "https://r.example.test/x", Default: "maybe"}
		}, licensekey.ErrInvalidClaims},
		{"issuer name", func(c *licensekey.Claims) { c.Issuer.Name = "" }, licensekey.ErrInvalidClaims},
		{"issuer portal over http", func(c *licensekey.Claims) { c.Issuer.PortalURL = "http://p.example.test" }, licensekey.ErrInvalidClaims},
		{"addon without entitlement", func(c *licensekey.Claims) {
			c.Entitlements = []limits.GrantKey{limits.GrantAIWorker}
			c.Addons = map[limits.GrantKey]licensekey.Addon{limits.GrantAssetCollector: {Image: "r.example.test/c"}}
		}, licensekey.ErrInvalidClaims},
		{"addon image with space", func(c *licensekey.Claims) {
			c.Addons = map[limits.GrantKey]licensekey.Addon{limits.GrantAIWorker: {Image: "r.example.test/w x"}}
		}, licensekey.ErrInvalidClaims},
		{"addon regexp", func(c *licensekey.Claims) {
			c.Addons = map[limits.GrantKey]licensekey.Addon{limits.GrantAIWorker: {Image: "r.example.test/w", CosignIdentityRegexp: "("}}
		}, licensekey.ErrInvalidClaims},
		{"addon min version", func(c *licensekey.Claims) {
			c.Addons = map[limits.GrantKey]licensekey.Addon{limits.GrantAIWorker: {Image: "r.example.test/w", MinVersion: "latest"}}
		}, licensekey.ErrInvalidClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lkt.Verifier().Verify(withClaims(tc.mut), licensekey.Options{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	full := withClaims(func(c *licensekey.Claims) {
		c.Type = licensekey.TypeNonProduction
		c.Addons = map[limits.GrantKey]licensekey.Addon{limits.GrantAIWorker: {
			Image: "registry.example.test/w", CosignIdentityRegexp: `^https://ci\.example\.test/.+$`,
			OIDCIssuer: "https://issuer.example.test", MinVersion: "0.9.0",
		}}
		c.Renewal = &licensekey.Renewal{URL: "https://r.example.test/v1/r/abc/current.octlic", Default: "on"}
		c.Meters = map[string]int64{"assets": 10000, "ai_worker.instances": 2}
	})
	if _, err := lkt.Verifier().Verify(full, licensekey.Options{}); err != nil {
		t.Fatalf("every optional claim: %v", err)
	}
}

// Claims are decoded strictly: unknown or duplicate keys are refused even
// when the issuer signed them.
func TestVerifyClaimsStrictDecode(t *testing.T) {
	payload := lkt.ClaimsPayload(lkt.Claims(now))
	extra := append(payload[:len(payload)-1:len(payload)-1], []byte(`,"seats_unlimited":true}`)...)
	dup := append(payload[:len(payload)-1:len(payload)-1], []byte(`,"type":"trial"}`)...)
	for name, p := range map[string][]byte{"unknown claim": extra, "duplicate claim": dup} {
		t.Run(name, func(t *testing.T) {
			file := lkt.Assemble(lkt.Envelope(lkt.IssuingKey(0), licensekey.PayloadType, p), lkt.DefaultKeySet(now).Sign())
			if _, err := lkt.Verifier().Verify(file, licensekey.Options{}); !errors.Is(err, licensekey.ErrMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestVerifyBinding(t *testing.T) {
	bound := withClaims(func(c *licensekey.Claims) {
		c.Bind = &licensekey.Binding{InstallationIDs: []string{"00000000-0000-4000-8000-000000000001", installID}}
	})
	unbound := signed(lkt.Claims(now))
	emptyBind := withClaims(func(c *licensekey.Claims) { c.Bind = &licensekey.Binding{} })
	cases := []struct {
		name string
		file []byte
		id   string
		want error
	}{
		{"bound, listed", bound, installID, nil},
		{"bound, listed upper-case", bound, strings.ToUpper(installID), nil},
		{"bound, other installation", bound, "11111111-2222-4333-8444-555555555555", licensekey.ErrBindingMismatch},
		{"bound, installation has no id", bound, "", licensekey.ErrBindingMismatch},
		{"unbound, any installation", unbound, "11111111-2222-4333-8444-555555555555", nil},
		{"unbound, no id", unbound, "", nil},
		{"empty binding is unbound", emptyBind, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lkt.Verifier().Verify(tc.file, licensekey.Options{InstallationID: tc.id})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStateAt(t *testing.T) {
	c := lkt.Claims(now)
	trial := lkt.Claims(now)
	trial.Type, trial.GraceDays, trial.ExpiresAt = licensekey.TypeTrial, intp(0), trial.NotBefore.Add(30*24*time.Hour)
	day := 24 * time.Hour
	cases := []struct {
		name string
		c    licensekey.Claims
		at   time.Time
		want licensekey.State
	}{
		{"before not_before", c, c.NotBefore.Add(-time.Second), licensekey.StateNotYetValid},
		{"at not_before", c, c.NotBefore, licensekey.StateActive},
		{"one second before the expiring window", c, c.ExpiresAt.Add(-licensekey.ExpiringWindow - time.Second), licensekey.StateActive},
		{"start of the expiring window", c, c.ExpiresAt.Add(-licensekey.ExpiringWindow), licensekey.StateExpiring},
		{"one second before expiry", c, c.ExpiresAt.Add(-time.Second), licensekey.StateExpiring},
		{"at expiry", c, c.ExpiresAt, licensekey.StateGrace},
		{"last second of grace", c, c.ExpiresAt.Add(14*day - time.Second), licensekey.StateGrace},
		{"end of grace", c, c.ExpiresAt.Add(14 * day), licensekey.StateExpired},
		{"long after", c, c.ExpiresAt.Add(400 * day), licensekey.StateExpired},
		{"trial expiring all along", trial, trial.NotBefore, licensekey.StateExpiring},
		{"trial has no grace", trial, trial.ExpiresAt, licensekey.StateExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.StateAt(tc.at); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	for s, granting := range map[licensekey.State]bool{
		licensekey.StateNotYetValid: false, licensekey.StateActive: true, licensekey.StateExpiring: true,
		licensekey.StateGrace: true, licensekey.StateExpired: false,
	} {
		if s.Granting() != granting {
			t.Errorf("%s.Granting() = %v", s, !granting)
		}
	}
}

// Winding the clock back cannot revive an expired license: states use the
// effective time, which never goes below the stored high-water mark or the
// newest stored issued_at.
func TestClockRollback(t *testing.T) {
	c := lkt.Claims(now)
	expiredAt := c.GraceEndsAt().Add(time.Hour)
	highWater := expiredAt // what the store recorded while the clock was right
	rolledBack := c.NotBefore.Add(24 * time.Hour)
	if got := c.StateAt(licensekey.EffectiveTime(rolledBack, highWater)); got != licensekey.StateExpired {
		t.Fatalf("clock rolled back revived the license: %s", got)
	}
	// A newer license's issued_at moves a clock that is behind forward.
	if got := licensekey.EffectiveTime(rolledBack, time.Time{}, c.IssuedAt, expiredAt); !got.Equal(expiredAt) {
		t.Fatalf("issued_at not honored: %s", got)
	}
	// A clock ahead of the mark is used as is.
	ahead := highWater.Add(48 * time.Hour)
	if got := licensekey.EffectiveTime(ahead, highWater, c.IssuedAt); !got.Equal(ahead) {
		t.Fatalf("got %s", got)
	}
	if got := licensekey.EffectiveTime(time.Time{}, time.Time{}); !got.IsZero() {
		t.Fatalf("zero inputs: %s", got)
	}
}

func TestReason(t *testing.T) {
	for err, want := range map[error]string{
		nil: "", licensekey.ErrTooLarge: "too_large", licensekey.ErrMalformed: "malformed",
		licensekey.ErrNoTrustedRoot: "no_trusted_root", licensekey.ErrUntrustedRoot: "untrusted_root",
		licensekey.ErrBadSignature: "bad_signature", licensekey.ErrKeySetRollback: "keyset_rollback",
		licensekey.ErrRevoked: "revoked", licensekey.ErrInvalidClaims: "invalid_claims",
		licensekey.ErrUnknownEntitlement: "unknown_entitlement", licensekey.ErrBindingMismatch: "binding_mismatch",
		errors.New("other"): "invalid",
	} {
		if got := licensekey.Reason(err); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
}

// Arbitrary input never panics and never verifies without a valid signature.
func FuzzVerify(f *testing.F) {
	file := signed(lkt.Claims(now))
	f.Add(file)
	f.Add([]byte(base64.StdEncoding.EncodeToString(file)))
	f.Add([]byte(`{"license":{},"keyset":{}}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		lic, err := lkt.Verifier().Verify(in, licensekey.Options{})
		if err == nil && lic.KeyID == "" {
			t.Fatal("verified without a signer")
		}
	})
}
