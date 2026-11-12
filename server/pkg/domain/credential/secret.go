package credential

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A leaked credential's secret (the password, token or key that leaked) is
// stored inside the exposure event's details. It is the most sensitive value
// the platform holds about a tenant, so:
//
//   - at rest it is encrypted with the platform credential key
//     (APP_ENCRYPTION_KEY, AES-256-GCM) under DetailSecretCiphertext;
//   - every read path returns only DetailSecretMasked and
//     DetailSecretFingerprint (see RedactDetails);
//   - the fingerprint is keyed per organization (HKDF of the platform key with
//     the tenant id), so the same secret leaked for two organizations has two
//     unrelated fingerprints and a database reader cannot link them;
//   - an organization may choose not to keep the value at all
//     (credentials.store_secret_values): the import then keeps only the mask,
//     the credential type and the fingerprint (Seal with store=false);
//   - the plaintext is returned only by the reveal endpoint, which requires
//     findings:credentials:reveal and writes an audit event.
//
// Rows written before this existed carry the plaintext under DetailSecretValue.
// They stay readable (Open falls back to it, RedactDetails masks it) until the
// backfill seals them.
const (
	// DetailSecretValue is the legacy plaintext key, and the key importers use.
	DetailSecretValue = "secret_value"
	// DetailSecretCiphertext holds the sealed secret.
	DetailSecretCiphertext = "secret_value_enc"
	// DetailSecretScheme records how DetailSecretCiphertext was sealed.
	DetailSecretScheme = "secret_enc_scheme"
	// DetailSecretMasked is a display-safe rendering of the secret.
	DetailSecretMasked = "secret_masked"
	// DetailSecretFingerprint is a keyed hash of the secret, for correlating
	// the same secret across leaks of one organization without revealing it.
	DetailSecretFingerprint = "secret_fingerprint"
	// DetailSecretFingerprintVersion is the fingerprint recipe of
	// DetailSecretFingerprint: FingerprintVersionTenant, or absent for the
	// install-wide recipe that the start-up re-key replaces.
	DetailSecretFingerprintVersion = "secret_fingerprint_version"

	// FingerprintVersionTenant is the per-organization fingerprint recipe.
	FingerprintVersionTenant = 2

	// SecretSchemeAESGCM means DetailSecretCiphertext is AES-256-GCM ciphertext.
	SecretSchemeAESGCM = "aes-256-gcm"
	// SecretSchemeNone means no encryption key was configured when the secret
	// was stored (development only); DetailSecretCiphertext is the plaintext.
	// The backfill re-seals these rows once a key is configured.
	SecretSchemeNone = "none"

	maskedSecret          = "********"
	maskPrefixMinLen      = 20
	maskPrefixLen         = 4
	fingerprintBytes      = 16
	fingerprintKeyContext = "openctem:leaked-credential-fingerprint:v1"
	// tenantFingerprintInfo is the HKDF info prefix of the per-organization
	// fingerprint key; the tenant id follows it.
	tenantFingerprintInfo = "openctem:credential-fingerprint:v2:"
)

// StoragePolicy answers, per organization, whether an imported leaked secret
// value is kept (encrypted). When it is not, only the mask, the credential
// type and the organization's fingerprint are stored.
type StoragePolicy interface {
	StoresSecretValues(ctx context.Context, tenantID shared.ID) bool
}

// ErrSecretUnreadable is returned when a stored secret cannot be decrypted
// (wrong or rotated key, corrupted row).
var ErrSecretUnreadable = errors.New("credential: stored secret cannot be decrypted")

// MaskSecret returns a display-safe rendering of a secret of the given
// credential type. Passwords, private keys and every other type are fully
// masked. Long API keys and tokens keep a four-character prefix, which names
// the token family ("AKIA", "ghp_") without giving away the secret. The
// masked length is fixed, so it does not leak the secret's length.
func MaskSecret(credType, secret string) string {
	r := []rune(secret)
	if len(r) == 0 {
		return ""
	}
	if len(r) >= maskPrefixMinLen && showsTokenPrefix(CredentialType(credType)) {
		return string(r[:maskPrefixLen]) + maskedSecret
	}
	return maskedSecret
}

// showsTokenPrefix lists the types whose prefix is a vendor marker rather than
// part of a human-chosen secret.
func showsTokenPrefix(t CredentialType) bool {
	switch t {
	case CredentialTypeAPIKey, CredentialTypeAccessToken, CredentialTypeRefreshToken,
		CredentialTypeAWSKey, CredentialTypeGCPKey, CredentialTypeAzureKey:
		return true
	}
	return false
}

func credTypeOf(details map[string]any) string {
	t, _ := details["credential_type"].(string)
	return t
}

// SecretProtector seals and opens the secret stored in a leaked-credential
// exposure's details.
type SecretProtector struct {
	enc  crypto.Encryptor
	real bool
	// fpPRK is the HKDF pseudo-random key the per-organization fingerprint
	// keys are expanded from.
	fpPRK []byte
	// fpKeyV1 is the install-wide fingerprint key, kept only to re-key rows
	// written with it and to reverse that re-key.
	fpKeyV1 []byte
}

// NewSecretProtector builds a protector. enc is the platform credential
// encryptor; a nil or no-op encryptor stores secrets with SecretSchemeNone
// (development only). keyMaterial keys the fingerprints (pass the platform
// encryption key string); it is never used directly as an HMAC key.
func NewSecretProtector(enc crypto.Encryptor, keyMaterial []byte) *SecretProtector {
	if enc == nil {
		enc = crypto.NewNoOpEncryptor()
	}
	h := sha256.New()
	h.Write([]byte(fingerprintKeyContext))
	h.Write(keyMaterial)
	// Extract fails only for a key too short for FIPS 140-only mode; the PRK
	// then stays nil and no fingerprint is produced (never an unkeyed one).
	prk, _ := hkdf.Extract(sha256.New, keyMaterial, []byte(tenantFingerprintInfo))
	return &SecretProtector{enc: enc, real: !crypto.IsNoOp(enc), fpPRK: prk, fpKeyV1: h.Sum(nil)}
}

// Encrypts reports whether secrets are actually encrypted at rest.
func (p *SecretProtector) Encrypts() bool { return p.real }

// tenantKey is the organization's fingerprint key:
// HKDF-SHA256(platform key, info = "openctem:credential-fingerprint:v2:" || tenant id).
// It is nil when no key can be derived (no PRK, or no tenant).
func (p *SecretProtector) tenantKey(tenantID shared.ID) []byte {
	if len(p.fpPRK) == 0 || tenantID.IsZero() {
		return nil
	}
	k, err := hkdf.Expand(sha256.New, p.fpPRK, tenantFingerprintInfo+tenantID.String(), sha256.Size)
	if err != nil {
		return nil
	}
	return k
}

// Fingerprint returns the organization's keyed fingerprint of a secret. The
// same secret has the same fingerprint inside one organization and unrelated
// fingerprints in two. It is "" when no key can be derived (no tenant).
func (p *SecretProtector) Fingerprint(tenantID shared.ID, secret string) string {
	key := p.tenantKey(tenantID)
	if key == nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil)[:fingerprintBytes])
}

// FingerprintV1 is the install-wide fingerprint the per-organization one
// replaced. Only the re-key and its reversal use it.
func (p *SecretProtector) FingerprintV1(secret string) string {
	mac := hmac.New(sha256.New, p.fpKeyV1)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil)[:fingerprintBytes])
}

// NeedsSealing reports whether details hold a secret that is not sealed the
// way this protector would seal it now: legacy plaintext, or a SchemeNone
// secret once a real key is configured.
func (p *SecretProtector) NeedsSealing(details map[string]any) bool {
	if legacyPlaintext(details) != "" {
		return true
	}
	return p.real && details[DetailSecretScheme] == SecretSchemeNone
}

// Seal protects the secret in details in place, for an organization. The
// plaintext is taken from DetailSecretValue (new import, or a legacy row) or,
// when a real key is now configured, from a SchemeNone ciphertext.
// Afterwards DetailSecretValue is gone and the mask, the per-organization
// fingerprint and its version are set. With store, the secret is also
// encrypted under DetailSecretCiphertext; without it no form of the value is
// kept (any older ciphertext is removed, it would belong to another value).
// Details without a secret are left untouched.
func (p *SecretProtector) Seal(tenantID shared.ID, details map[string]any, store bool) error {
	if details == nil {
		return nil
	}
	plaintext := legacyPlaintext(details)
	if plaintext == "" && p.real && details[DetailSecretScheme] == SecretSchemeNone {
		plaintext, _ = details[DetailSecretCiphertext].(string)
	}
	delete(details, DetailSecretValue)
	if plaintext == "" {
		return nil
	}
	details[DetailSecretMasked] = MaskSecret(credTypeOf(details), plaintext)
	if fp := p.Fingerprint(tenantID, plaintext); fp != "" {
		details[DetailSecretFingerprint] = fp
		details[DetailSecretFingerprintVersion] = FingerprintVersionTenant
	} else {
		delete(details, DetailSecretFingerprint)
		delete(details, DetailSecretFingerprintVersion)
	}
	if !store {
		delete(details, DetailSecretCiphertext)
		delete(details, DetailSecretScheme)
		return nil
	}
	sealed, err := p.enc.EncryptString(plaintext)
	if err != nil {
		return fmt.Errorf("seal leaked credential secret: %w", err)
	}
	scheme := SecretSchemeNone
	if p.real {
		scheme = SecretSchemeAESGCM
	}
	details[DetailSecretCiphertext] = sealed
	details[DetailSecretScheme] = scheme
	return nil
}

// FingerprintOutcome is what RekeyFingerprint or RevertFingerprint did to
// one row's details.
type FingerprintOutcome int

// Fingerprint re-key outcomes.
const (
	// FingerprintUnchanged: already in the wanted recipe, or no fingerprint.
	FingerprintUnchanged FingerprintOutcome = iota
	// FingerprintRekeyed: the fingerprint was recomputed from the stored secret.
	FingerprintRekeyed
	// FingerprintUnrecomputable: the row has a fingerprint in the old recipe
	// but its secret cannot be opened (wrong key, or no stored value); the
	// details are left as they are.
	FingerprintUnrecomputable
)

// HasTenantFingerprint reports whether details' fingerprint is in the
// per-organization recipe. JSON decodes the version as a float64.
func HasTenantFingerprint(details map[string]any) bool {
	switch v := details[DetailSecretFingerprintVersion].(type) {
	case int:
		return v == FingerprintVersionTenant
	case float64:
		return v == FingerprintVersionTenant
	case json.Number:
		return v.String() == fmt.Sprint(FingerprintVersionTenant)
	}
	return false
}

// RekeyFingerprint moves details' fingerprint to the per-organization recipe
// of tenantID, recomputing it from the stored secret. It is idempotent: a
// fingerprint already in that recipe is left alone.
func (p *SecretProtector) RekeyFingerprint(tenantID shared.ID, details map[string]any) FingerprintOutcome {
	if HasTenantFingerprint(details) {
		return FingerprintUnchanged
	}
	if fp, _ := details[DetailSecretFingerprint].(string); fp == "" {
		return FingerprintUnchanged
	}
	plain, ok, err := p.Open(details)
	if err != nil || !ok || plain == "" {
		return FingerprintUnrecomputable
	}
	fp := p.Fingerprint(tenantID, plain)
	if fp == "" {
		return FingerprintUnrecomputable
	}
	details[DetailSecretFingerprint] = fp
	details[DetailSecretFingerprintVersion] = FingerprintVersionTenant
	return FingerprintRekeyed
}

// RevertFingerprint is the reverse of RekeyFingerprint: it puts back the
// install-wide fingerprint computed from the stored secret and removes the
// version, for a rollback to a build that only knows that recipe. A row
// without a stored secret keeps its per-organization fingerprint.
func (p *SecretProtector) RevertFingerprint(details map[string]any) FingerprintOutcome {
	if !HasTenantFingerprint(details) {
		return FingerprintUnchanged
	}
	plain, ok, err := p.Open(details)
	if err != nil || !ok || plain == "" {
		return FingerprintUnrecomputable
	}
	details[DetailSecretFingerprint] = p.FingerprintV1(plain)
	delete(details, DetailSecretFingerprintVersion)
	return FingerprintRekeyed
}

// Open returns the plaintext secret held in details. ok is false when there is
// no secret. A legacy plaintext row is returned as is.
func (p *SecretProtector) Open(details map[string]any) (secret string, ok bool, err error) {
	if ct, _ := details[DetailSecretCiphertext].(string); ct != "" {
		if details[DetailSecretScheme] == SecretSchemeNone {
			return ct, true, nil
		}
		plain, derr := p.enc.DecryptString(ct)
		if derr != nil || !p.real {
			return "", true, ErrSecretUnreadable
		}
		return plain, true, nil
	}
	if s := legacyPlaintext(details); s != "" {
		return s, true, nil
	}
	return "", false, nil
}

// legacyPlaintext returns the plaintext stored under DetailSecretValue. JSON
// written by hand or by old importers may hold a number there; it is still a
// secret.
func legacyPlaintext(details map[string]any) string {
	switch v := details[DetailSecretValue].(type) {
	case nil:
		return ""
	case string:
		return v
	case map[string]any, []any:
		b, _ := json.Marshal(v)
		return string(b)
	default:
		return fmt.Sprint(v)
	}
}

// HasSecret reports whether details carry a secret, sealed or legacy.
func HasSecret(details map[string]any) bool {
	if s, _ := details[DetailSecretCiphertext].(string); s != "" {
		return true
	}
	return legacyPlaintext(details) != ""
}

// RedactDetails returns a copy of details that is safe to return to any
// reader: the plaintext and the ciphertext are removed, and a legacy plaintext
// row gets a mask computed on the fly. It is applied to every exposure read,
// not only credentials, because generic exposure endpoints serve the same rows.
func RedactDetails(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	out := make(map[string]any, len(details))
	for k, v := range details {
		out[k] = v
	}
	if legacy := legacyPlaintext(details); legacy != "" {
		if _, has := out[DetailSecretMasked]; !has {
			out[DetailSecretMasked] = MaskSecret(credTypeOf(details), legacy)
		}
	}
	delete(out, DetailSecretValue)
	delete(out, DetailSecretCiphertext)
	delete(out, DetailSecretScheme)
	return redactSensitiveKeys(out)
}

// RedactedValue replaces the value of a sensitive details key.
const RedactedValue = "********"

var sensitiveKeyExact = map[string]bool{
	"password": true, "passwd": true, "api_key": true, "apikey": true,
	"token": true, "access_token": true, "refresh_token": true,
	"private_key": true, "privatekey": true, "secret": true,
	"client_secret": true, "credential": true, "credentials": true,
	"secret_access_key": true, "aws_secret_access_key": true,
	"connection_string": true, "dsn": true,
}

// secretMetadataSuffixes are the `secret_<x>` keys that describe a secret
// (its type, validity, rotation state) without carrying it. They stay verbatim.
var secretMetadataSuffixes = map[string]bool{
	"type": true, "valid": true, "revoked": true, "entropy": true,
	"needs_rotation": true, "expires_at": true, "masked": true,
	"masked_value": true, "fingerprint": true, "fingerprint_prefix": true,
	"fingerprint_version": true,
	"id":                  true, "set": true, "changed": true, "service": true,
	"pre_existing": true, "not_observed": true, "detection": true,
	"scan": true, "source": true, "provider": true, "kind": true,
	"status": true, "name": true, "length": true, "count": true,
}

var sensitiveKeySuffixes = []string{"_password", "_passwd", "_token", "_api_key", "_secret", "_private_key"}

// isSensitiveDetailKey reports whether a details key carries a tool-reported
// secret. The masked value and the keyed fingerprint are safe by design.
func isSensitiveDetailKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if k == DetailSecretMasked || k == DetailSecretFingerprint {
		return false
	}
	if sensitiveKeyExact[k] {
		return true
	}
	if rest, ok := strings.CutPrefix(k, "secret_"); ok {
		return !secretMetadataSuffixes[rest]
	}
	for _, suf := range sensitiveKeySuffixes {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// redactSensitiveKeys masks every sensitive key, recursively through nested
// maps and arrays. It builds new containers and never mutates its input.
func redactSensitiveKeys(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveDetailKey(k) {
			out[k] = RedactedValue
			continue
		}
		out[k] = redactSensitiveValue(v)
	}
	return out
}

func redactSensitiveValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return redactSensitiveKeys(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactSensitiveValue(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactSensitiveKeys(e)
		}
		return out
	default:
		return v
	}
}
