package credential

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/crypto"
)

// A leaked credential's secret (the password, token or key that leaked) is
// stored inside the exposure event's details. It is the most sensitive value
// the platform holds about a tenant, so:
//
//   - at rest it is encrypted with the platform credential key
//     (APP_ENCRYPTION_KEY, AES-256-GCM) under DetailSecretCiphertext;
//   - every read path returns only DetailSecretMasked and
//     DetailSecretFingerprint (see RedactDetails);
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
	// the same secret across leaks without revealing it.
	DetailSecretFingerprint = "secret_fingerprint"

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
)

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
	enc   crypto.Encryptor
	real  bool
	fpKey []byte
}

// NewSecretProtector builds a protector. enc is the platform credential
// encryptor; a nil or no-op encryptor stores secrets with SecretSchemeNone
// (development only). keyMaterial keys the fingerprint HMAC (pass the
// platform encryption key); it is never used directly as an HMAC key.
func NewSecretProtector(enc crypto.Encryptor, keyMaterial []byte) *SecretProtector {
	if enc == nil {
		enc = crypto.NewNoOpEncryptor()
	}
	h := sha256.New()
	h.Write([]byte(fingerprintKeyContext))
	h.Write(keyMaterial)
	return &SecretProtector{enc: enc, real: !crypto.IsNoOp(enc), fpKey: h.Sum(nil)}
}

// Encrypts reports whether secrets are actually encrypted at rest.
func (p *SecretProtector) Encrypts() bool { return p.real }

// Fingerprint returns the keyed fingerprint of a secret.
func (p *SecretProtector) Fingerprint(secret string) string {
	mac := hmac.New(sha256.New, p.fpKey)
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

// Seal encrypts the secret in details in place. The plaintext is taken from
// DetailSecretValue (new import, or a legacy row) or, when a real key is now
// configured, from a SchemeNone ciphertext. Afterwards DetailSecretValue is
// gone and the ciphertext, scheme, mask and fingerprint are set. Details
// without a secret are left untouched.
func (p *SecretProtector) Seal(details map[string]any) error {
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
	details[DetailSecretMasked] = MaskSecret(credTypeOf(details), plaintext)
	details[DetailSecretFingerprint] = p.Fingerprint(plaintext)
	return nil
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
	return out
}
