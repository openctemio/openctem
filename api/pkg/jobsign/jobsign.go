// Package jobsign is the wire format of signed jobs: the job statement the
// API asks the signer (cmd/signer) to sign, the DSSE envelope the signer
// returns and a sensor verifies before it runs a command, and the key ids.
// Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.6; the
// exact format is in docs/architecture/job-signing.md.
//
// The package imports only the standard library and the DSSE helpers of
// scannertemplate, so the signer process can use it without linking any of
// the API's application or infrastructure code.
package jobsign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// PayloadType is the DSSE payload type of a signed job.
const PayloadType = "application/vnd.openctem.job.v1+json"

// Kind is the statement kind (v1).
const Kind = "openctem.job/v1"

// Algorithm is the signature algorithm of every key the signer holds.
const Algorithm = "ed25519"

// Limits the signer enforces on a statement.
const (
	// MaxStatementBytes caps the body of a sign request.
	MaxStatementBytes = 1 << 20
	// MaxTargets caps the targets of one statement.
	MaxTargets = 10000
	// MaxTargetBytes caps one target.
	MaxTargetBytes = 1024
	// MaxTemplates caps the custom templates of one statement.
	MaxTemplates = 256
	// MaxTTL caps expires_at - issued_at.
	MaxTTL = time.Hour
	// MaxClockSkew is how far issued_at may be from the signer's clock.
	MaxClockSkew = 2 * time.Minute
	// NonceBytes is the size of a nonce before encoding.
	NonceBytes = 16
)

// Statement is a job statement. The API sends it without Seq, Nonce and
// Signer; the signer validates it, sets those three and signs the JSON
// encoding of this struct, field order as declared. A verifier never
// re-encodes it: it hashes and parses the envelope's payload bytes.
type Statement struct {
	Kind        string `json:"kind"`
	TenantID    string `json:"tenant_id"`
	SensorID    string `json:"sensor_id"`
	CommandID   string `json:"command_id"`
	CommandType string `json:"command_type"`
	// Tool is the tool the command names (payload "scanner", else
	// "preferred_tool"); "" for a command that names none.
	Tool string `json:"tool"`
	// PayloadSHA256 is "sha256:" + lower-case hex of the SHA-256 of the
	// command's "payload" JSON value, as the exact bytes of the response
	// that hands the command to the sensor.
	PayloadSHA256 string   `json:"payload_sha256"`
	Targets       []string `json:"targets"`
	// Templates is "sha256:" + lower-case hex of the SHA-256 of each custom
	// template the payload carries (payload custom_templates[].content,
	// base64-decoded), in payload order; absent when it carries none. The
	// signer signs only digests in its ledger, and a sensor that verified
	// the statement trusts exactly these template bytes.
	Templates []string `json:"templates,omitempty"`
	// Limits are the port, protocol and path limits of the targets only
	// limited scope entries cover (limits.go), for a sensor that enforces
	// them (CapabilityScopeLimits). The signer signs a limit only when an
	// entry of its ledger that covers the target allows it, and a crawler
	// or template scanner on such a target only with limits. A sensor that
	// does not know the field refuses the statement.
	Limits     []Limit   `json:"limits,omitempty"`
	LeaseEpoch int       `json:"lease_epoch"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Seq, Nonce and Signer are set by the signer.
	Seq    uint64     `json:"seq"`
	Nonce  string     `json:"nonce"`
	Signer *SignerRef `json:"signer"`
}

// SignerRef names the key that signed a statement.
type SignerRef struct {
	KeyID string `json:"keyid"`
}

// PublicKey is one signer key as GET /v1/keys and the sensor hello list it.
type PublicKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	// PublicKey is the raw 32-byte Ed25519 key, standard base64.
	PublicKey string `json:"public_key"`
}

// KeysResponse is the body of GET /v1/keys.
type KeysResponse struct {
	PayloadType string      `json:"payload_type"`
	Keys        []PublicKey `json:"keys"`
}

// Refusal is the body of a refused sign request.
type Refusal struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// KeyID names a public key: "SHA256:" + lower-case hex of the SHA-256 of
// the raw 32-byte key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// NewPublicKey describes pub.
func NewPublicKey(pub ed25519.PublicKey) PublicKey {
	return PublicKey{KeyID: KeyID(pub), Algorithm: Algorithm, PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

// Decode returns the raw key of k after checking its id matches it.
func (k PublicKey) Decode() (ed25519.PublicKey, error) {
	if k.Algorithm != Algorithm {
		return nil, fmt.Errorf("signer key %s: unsupported algorithm %q", k.KeyID, k.Algorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer key %s: not a 32-byte Ed25519 key", k.KeyID)
	}
	pub := ed25519.PublicKey(raw)
	if KeyID(pub) != k.KeyID {
		return nil, fmt.Errorf("signer key %s: id does not match the key", k.KeyID)
	}
	return pub, nil
}

// PayloadDigest is the payload_sha256 of payload bytes.
func PayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidDigest reports whether d is "sha256:" + 64 lower-case hex characters.
func ValidDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Sign signs payload with priv and returns the envelope. The payload is
// signed as is: the caller serializes the statement exactly once.
func Sign(priv ed25519.PrivateKey, payload []byte) scannertemplate.Envelope {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return scannertemplate.Envelope{
		PayloadType: PayloadType,
		Payload:     payload,
		Signatures: []scannertemplate.EnvelopeSignature{{
			KeyID: KeyID(pub),
			Sig:   ed25519.Sign(priv, scannertemplate.PreAuthEncoding(PayloadType, payload)),
		}},
	}
}

// Verify checks a signed-job envelope (JSON) against the trusted keys and
// returns its statement. It checks the signature, the payload type and the
// statement kind only: binding (ids, expiry, nonce, seq, lease epoch,
// payload digest) is the caller's, as docs/architecture/job-signing.md
// lists. It is the reference for the sensor's verifier.
func Verify(envelope []byte, trusted []ed25519.PublicKey) (*Statement, error) {
	var env scannertemplate.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("signed job: %w", err)
	}
	if env.PayloadType != PayloadType {
		return nil, errors.New("signed job: wrong payload type")
	}
	pae := scannertemplate.PreAuthEncoding(env.PayloadType, env.Payload)
	ok := false
	for _, sig := range env.Signatures {
		for _, pub := range trusted {
			if sig.KeyID == KeyID(pub) && ed25519.Verify(pub, pae, sig.Sig) {
				ok = true
			}
		}
	}
	if !ok {
		return nil, errors.New("signed job: not signed by a trusted key")
	}
	var st Statement
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return nil, fmt.Errorf("signed job: %w", err)
	}
	if st.Kind != Kind {
		return nil, errors.New("signed job: unknown statement kind")
	}
	return &st, nil
}
