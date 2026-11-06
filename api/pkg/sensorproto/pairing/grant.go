package pairing

// The signed grant: the platform's statement of everything a sensor pins at
// pairing, signed with the same pairing key the start answer was signed with
// and the short authentication string covers.
//
// Why: the start answer is the only message the person comparing the SAS
// vouches for. Everything the sensor learned after it (the identity, the
// content-signing keys, the job-signing key set and the platform TLS anchor)
// came unsigned, so a man in the middle of the first pairing could
// relay the start untouched (the SAS still matches) and then swap those.
// The platform now signs them in one statement bound to this pairing, this
// sensor's key and its revealed nonce, and the sensor verifies it with the
// key from the start answer before it saves anything. The statement is
// signed as opaque bytes (no canonical JSON): the sensor decodes the
// payload it verified and uses only that.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// domainGrant separates the grant signature from every other pairing
// signature.
const domainGrant = "openctem/sensor-pairing/grant/v1"

// ProblemAnswerUnsigned is the name a sensor reports (and logs) when an
// approval or confirm answer carries no valid platform signature.
const ProblemAnswerUnsigned = "pairing_answer_unsigned"

var (
	// ErrGrantMissing is an approval or confirm answer without a signed
	// grant: a platform from before signed pairing answers, or someone in
	// the middle who removed it. The sensor never pairs without it.
	ErrGrantMissing = errors.New("pairing: the platform's answer is not signed (" + ProblemAnswerUnsigned + "): " +
		"upgrade the platform to a release that signs pairing answers, then pair again")
	// ErrGrantSignature is a signed grant that does not verify with the
	// platform key of the start answer, or that is malformed.
	ErrGrantSignature = errors.New("pairing: the platform's signature over its answer does not verify (" + ProblemAnswerUnsigned + "): " +
		"something between this sensor and the platform changed the answer")
	// ErrGrantBinding is a validly signed grant made for another pairing,
	// another sensor key or another nonce (a replay).
	ErrGrantBinding = errors.New("pairing: the platform's signed answer was made for another pairing request (" + ProblemAnswerUnsigned + ")")
)

// SignedGrant is the grant as it travels: the JSON statement (Grant) in
// base64url, and the platform's Ed25519 signature over
// domain ‖ 0 ‖ payload bytes, base64url.
type SignedGrant struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Grant is the statement the platform signs. Every value a sensor pins at
// pairing comes from it.
type Grant struct {
	// Protocol is Version.
	Protocol string `json:"protocol"`
	// PairingID, SensorKey (base64url raw Ed25519 key) and SensorNonce (the
	// nonce the sensor revealed, base64url) bind the grant to one request
	// of one sensor: a grant is never valid for another.
	PairingID   string `json:"pairing_id"`
	SensorKey   string `json:"sensor_key"`
	SensorNonce string `json:"sensor_nonce"`
	// Identity is what the approval granted, with its content-signing keys.
	Identity Identity `json:"identity"`
	// SignedJobs is the job signer's keys and key set, as the platform's
	// hello serves them now; nil from a platform that does not sign jobs.
	SignedJobs *JobSigning `json:"signed_jobs,omitempty"`
	// TLSAnchors are the SHA-256 fingerprints ("sha256:<64 hex>") of the
	// SubjectPublicKeyInfo of the root CAs that sign the platform's TLS
	// certificate, when the platform knows them (a private CA it was
	// configured with). Set, the anchor the sensor's pairing connections
	// verified must be one of them. Empty: the platform makes no claim (a
	// publicly trusted certificate), and the sensor pins the anchor it saw.
	TLSAnchors []string `json:"tls_anchors,omitempty"`
}

// JobSigning is the job signer's description in a grant: the same fields as
// the hello's signed_jobs block.
type JobSigning struct {
	PayloadType string   `json:"payload_type"`
	Keys        []JobKey `json:"keys"`
	// KeySet is the root-signed key set envelope (DSSE), as served.
	KeySet json.RawMessage `json:"keyset,omitempty"`
}

// JobKey is one job signer key, in the hello's form: KeyID "SHA256:" + hex,
// PublicKey the raw key in standard base64. A sensor recomputes the id.
type JobKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// GrantTranscript is what the platform signs: domain ‖ 0 ‖ payload.
func GrantTranscript(payload []byte) []byte {
	out := append([]byte(domainGrant), 0)
	return append(out, payload...)
}

// SignGrant encodes g and signs it with the platform pairing key.
func SignGrant(key ed25519.PrivateKey, g *Grant) (*SignedGrant, error) {
	if g == nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("pairing: a grant and the platform key are required")
	}
	g.Protocol = Version
	payload, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return &SignedGrant{Payload: Encode(payload), Signature: Encode(ed25519.Sign(key, GrantTranscript(payload)))}, nil
}

// VerifyGrant checks a signed grant with the platform key of the verified
// start answer and returns the statement, which must name this pairing,
// this sensor's key and the nonce it revealed. Nothing from an answer that
// fails here may be used.
func VerifyGrant(sg *SignedGrant, platformPub, sensorPub ed25519.PublicKey, pairingID string, sensorNonce []byte) (*Grant, error) {
	if sg == nil || sg.Payload == "" || sg.Signature == "" {
		return nil, ErrGrantMissing
	}
	if len(platformPub) != ed25519.PublicKeySize {
		return nil, ErrGrantSignature
	}
	payload, err := b64url.DecodeString(sg.Payload)
	if err != nil {
		return nil, ErrGrantSignature
	}
	sig, err := DecodeFixed(sg.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(platformPub, GrantTranscript(payload), sig) {
		return nil, ErrGrantSignature
	}
	var g Grant
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGrantSignature, err)
	}
	if g.Protocol != Version {
		return nil, fmt.Errorf("%w: protocol %q", ErrGrantBinding, g.Protocol)
	}
	key, err := DecodeKey(g.SensorKey)
	if err != nil || !bytes.Equal(key, sensorPub) || g.PairingID != pairingID {
		return nil, ErrGrantBinding
	}
	n, err := DecodeFixed(g.SensorNonce, NonceSize)
	if err != nil || len(sensorNonce) != NonceSize || !bytes.Equal(n, sensorNonce) {
		return nil, ErrGrantBinding
	}
	return &g, nil
}
