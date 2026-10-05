// Package pairing is the interactive sensor pairing protocol (api RFC-052):
// a sensor that has only the platform URL creates its own Ed25519 key, asks
// the platform to pair, and an administrator approves it after comparing a
// short authentication string (SAS) shown on both sides. No secret is ever
// typed, copied or pasted: the pairing code and the SAS are public.
//
// Exchange (all under /api/v2/sensor, every sensor request signed with the
// new key, see pkg/sensorsig):
//
//  1. POST /pairings               public key, commitment H(sensor nonce),
//     host facts, optional code (reverse mode)
//     → pairing id, user code, platform key, platform nonce, platform
//     signature, expiry
//  2. PUT  /pairings/{id}/nonce     the sensor nonce (the platform checks it
//     against the commitment; only now can either side compute the SAS)
//  3. GET  /pairings/{id}           poll until approved, denied or expired
//  4. POST /pairings/{id}/complete  the sensor confirms the identity it was
//     given; the key becomes active
//
// The sensor commits to its nonce before it sees the platform's, and the
// platform's nonce is fixed before the sensor reveals its own, so a
// man-in-the-middle gets one guess at a matching SAS (about 2^-34) instead
// of grinding nonces until both sides show the same words.
//
// Everything in this file is deterministic and covered by the shared test
// vectors (testdata/vectors.json, identical in sdk-go).
//
// The same package lives in sdk-go (pkg/sensorproto/pairing); the shared
// test vectors (testdata/vectors.json) are byte-identical in both.
package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Protocol constants.
const (
	// Version is the protocol identifier carried in StartRequest.
	Version = "openctem-pairing/v1"

	// Paths, relative to the v2 prefix /api/v2/sensor.
	StartPath   = "/pairings"
	StatusPath  = "/pairings/{pairing_id}"
	RevealPath  = "/pairings/{pairing_id}/nonce"
	ConfirmPath = "/pairings/{pairing_id}/complete"

	// NonceSize is the size of both nonces, in bytes.
	NonceSize = 32
	// CodeLength is the length of a user code without its separator.
	CodeLength = 8
	// CodeAlphabet is Crockford base32 (no I, L, O, U).
	CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// TTL is how long a pairing request stays open.
	TTL = 10 * time.Minute

	// Domain separators. Every hash or signature input starts with one and
	// a zero byte, so no value of one kind is ever valid as another.
	domainSAS      = "openctem/sensor-pairing/sas/v1"
	domainCommit   = "openctem/sensor-pairing/commit/v1"
	domainPlatform = "openctem/sensor-pairing/platform/v1"
	domainConfirm  = "openctem/sensor-pairing/confirm/v1"
)

// Status values of a pairing.
const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusCompleted = "completed"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
)

var (
	b64url = base64.RawURLEncoding

	// ErrBadCode is a user code that is not 8 Crockford base32 characters.
	ErrBadCode = errors.New("pairing: the code must be 8 characters (letters and digits)")
	// ErrCommitment is a revealed nonce that does not match the commitment.
	ErrCommitment = errors.New("pairing: nonce does not match the commitment")
	// ErrPlatformSignature is a platform reply whose signature fails.
	ErrPlatformSignature = errors.New("pairing: platform signature does not verify")
	// ErrPlatformKeyPin is a platform key other than the pinned one.
	ErrPlatformKeyPin = errors.New("pairing: platform key does not match the pinned fingerprint")
)

// HostFacts describe the sensor host. They are claims for the
// administrator to read, never used to authorize anything.
type HostFacts struct {
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	SensorVersion string `json:"sensor_version,omitempty"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	Product       string `json:"product,omitempty"`
	InstanceID    string `json:"instance_id,omitempty"`
	// Name is the name the operator asked for (SENSOR_NAME); the
	// administrator may change it.
	Name string `json:"name,omitempty"`
}

// StartRequest is the body of POST /pairings.
type StartRequest struct {
	Protocol string `json:"protocol"`
	// PublicKey is the sensor's Ed25519 public key (base64url, raw 32
	// bytes). The request is signed with it.
	PublicKey string `json:"public_key"`
	// Commitment is Commit(sensor nonce), base64url.
	Commitment string `json:"commitment"`
	// Code is the code an administrator created with "expect a sensor"
	// (reverse mode); empty in the default mode, where the platform
	// returns a code for the administrator to enter.
	Code string    `json:"code,omitempty"`
	Host HostFacts `json:"host"`
	// SensorID asks to re-pair this existing registration (lost or
	// compromised key). The administrator must approve it like a new one.
	SensorID string `json:"sensor_id,omitempty"`
}

// StartResponse is the 201 answer to POST /pairings. The answer has the same
// shape whether or not a reverse-mode code was valid.
type StartResponse struct {
	PairingID string `json:"pairing_id"`
	// UserCode is the code to enter in the console (default mode only),
	// formatted XXXX-XXXX.
	UserCode          string    `json:"user_code,omitempty"`
	PlatformKey       string    `json:"platform_key"`
	PlatformNonce     string    `json:"platform_nonce"`
	PlatformSignature string    `json:"platform_signature"`
	ExpiresAt         time.Time `json:"expires_at"`
	PollSeconds       int       `json:"poll_interval_seconds"`
}

// RevealRequest is the body of PUT /pairings/{id}/nonce.
type RevealRequest struct {
	SensorNonce string `json:"sensor_nonce"`
}

// Identity is what an approved pairing grants the sensor.
type Identity struct {
	SensorID   string    `json:"sensor_id"`
	TenantID   string    `json:"tenant_id"`
	TenantName string    `json:"tenant_name,omitempty"`
	Name       string    `json:"name"`
	KeyID      string    `json:"key_id"`
	ApprovedAt time.Time `json:"approved_at"`
	// Repair is true when the pairing replaced the key of an existing
	// registration.
	Repair bool `json:"repair,omitempty"`
}

// StatusResponse is the answer to GET /pairings/{id}.
type StatusResponse struct {
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	PollSeconds int       `json:"poll_interval_seconds"`
	Identity    *Identity `json:"identity,omitempty"`
}

// ConfirmRequest is the body of POST /pairings/{id}/complete: the sensor's
// acceptance of the identity, signed (ConfirmTranscript) with its key on
// top of the request signature, so the platform keeps a statement the
// sensor made about exactly this identity.
type ConfirmRequest struct {
	SensorID  string `json:"sensor_id"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// NewNonce returns NonceSize random bytes.
func NewNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// Commit is the commitment to a sensor nonce: SHA-256(domain ‖ 0 ‖ nonce).
func Commit(sensorNonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domainCommit))
	h.Write([]byte{0})
	h.Write(sensorNonce)
	return h.Sum(nil)
}

// CheckCommitment reports whether sensorNonce opens commitment.
func CheckCommitment(commitment, sensorNonce []byte) error {
	if len(sensorNonce) != NonceSize || len(commitment) != sha256.Size {
		return ErrCommitment
	}
	got := Commit(sensorNonce)
	var v byte
	for i := range got {
		v |= got[i] ^ commitment[i]
	}
	if v != 0 {
		return ErrCommitment
	}
	return nil
}

// PlatformTranscript is what the platform signs in its StartResponse:
// domain ‖ 0 ‖ pairing id ‖ 0 ‖ sensor key ‖ commitment ‖ platform key ‖
// platform nonce ‖ expiry (Unix seconds, big-endian uint64).
func PlatformTranscript(pairingID string, sensorPub, commitment, platformPub, platformNonce []byte, expires time.Time) []byte {
	out := make([]byte, 0, len(domainPlatform)+1+len(pairingID)+1+32+32+32+32+8)
	out = append(out, domainPlatform...)
	out = append(out, 0)
	out = append(out, pairingID...)
	out = append(out, 0)
	out = append(out, sensorPub...)
	out = append(out, commitment...)
	out = append(out, platformPub...)
	out = append(out, platformNonce...)
	out = binary.BigEndian.AppendUint64(out, uint64(expires.Unix())) //nolint:gosec // Unix time after 1970
	return out
}

// ConfirmTranscript is what the sensor signs in ConfirmRequest:
// domain ‖ 0 ‖ pairing id ‖ 0 ‖ sensor id ‖ 0 ‖ tenant id ‖ 0 ‖ key id.
func ConfirmTranscript(pairingID, sensorID, tenantID, keyID string) []byte {
	return []byte(domainConfirm + "\x00" + pairingID + "\x00" + sensorID + "\x00" + tenantID + "\x00" + keyID)
}

// SAS is the short authentication string both sides show.
type SAS struct {
	// Number is three digits, "000"-"999".
	Number string `json:"number"`
	// Words are three words from Words.
	Words [3]string `json:"words"`
}

// String renders the SAS as "512 · tiger · violet · anchor".
func (s SAS) String() string {
	return s.Number + " · " + strings.Join(s.Words[:], " · ")
}

// ComputeSAS derives the SAS: d = SHA-256(domain ‖ 0 ‖ sensor key ‖
// platform key ‖ sensor nonce ‖ platform nonce); the number is
// (d[0]·256 + d[1]) mod 1000 and the words are Words[d[2]], Words[d[3]],
// Words[d[4]] (about 34 bits).
func ComputeSAS(sensorPub, platformPub, sensorNonce, platformNonce []byte) SAS {
	h := sha256.New()
	h.Write([]byte(domainSAS))
	h.Write([]byte{0})
	h.Write(sensorPub)
	h.Write(platformPub)
	h.Write(sensorNonce)
	h.Write(platformNonce)
	d := h.Sum(nil)
	n := (int(d[0])<<8 | int(d[1])) % 1000
	return SAS{Number: fmt.Sprintf("%03d", n), Words: [3]string{Words[d[2]], Words[d[3]], Words[d[4]]}}
}

// WordsDigest is the SHA-256 (hex) of the word list, one word per line with
// a trailing newline; the test vectors pin it.
func WordsDigest() string {
	h := sha256.New()
	for _, w := range &Words {
		h.Write([]byte(w + "\n"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// NewCode returns a random user code (40 bits), unformatted.
func NewCode() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return encodeCode(b), nil
}

func encodeCode(b [5]byte) string {
	v := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	out := make([]byte, CodeLength)
	for i := CodeLength - 1; i >= 0; i-- {
		out[i] = CodeAlphabet[v&31]
		v >>= 5
	}
	return string(out)
}

// NormalizeCode returns the canonical form of a typed code: upper case,
// separators and spaces removed, O read as 0 and I/L as 1.
func NormalizeCode(s string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(CodeAlphabet, r) {
			return "", ErrBadCode
		}
		b.WriteRune(r)
	}
	if b.Len() != CodeLength {
		return "", ErrBadCode
	}
	return b.String(), nil
}

// FormatCode renders a canonical code as XXXX-XXXX.
func FormatCode(code string) string {
	if len(code) != CodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// KeyFingerprint is how a key is shown to people: "SHA256:" followed by its
// RFC 7638 thumbprint.
func KeyFingerprint(thumbprint string) string { return "SHA256:" + thumbprint }

// DecodeKey decodes a base64url Ed25519 public key.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := b64url.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("pairing: invalid public key")
	}
	return ed25519.PublicKey(b), nil
}

// DecodeFixed decodes base64url bytes of an exact size.
func DecodeFixed(s string, size int) ([]byte, error) {
	b, err := b64url.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("pairing: expected %d bytes", size)
	}
	return b, nil
}

// Encode is base64url without padding, the encoding of every binary field.
func Encode(b []byte) string { return b64url.EncodeToString(b) }

// VerifyStart checks a StartResponse against what the sensor sent: the
// platform signature over the transcript, and the platform key against
// pinnedThumbprint when one is set (from the install snippet).
func VerifyStart(resp *StartResponse, sensorPub ed25519.PublicKey, commitment []byte, pinnedThumbprint string, thumbprint func(ed25519.PublicKey) string) (platformPub ed25519.PublicKey, platformNonce []byte, err error) {
	platformPub, err = DecodeKey(resp.PlatformKey)
	if err != nil {
		return nil, nil, err
	}
	if pinnedThumbprint != "" && thumbprint(platformPub) != strings.TrimPrefix(pinnedThumbprint, "SHA256:") {
		return nil, nil, ErrPlatformKeyPin
	}
	platformNonce, err = DecodeFixed(resp.PlatformNonce, NonceSize)
	if err != nil {
		return nil, nil, err
	}
	sig, err := DecodeFixed(resp.PlatformSignature, ed25519.SignatureSize)
	if err != nil {
		return nil, nil, err
	}
	msg := PlatformTranscript(resp.PairingID, sensorPub, commitment, platformPub, platformNonce, resp.ExpiresAt)
	if !ed25519.Verify(platformPub, msg, sig) {
		return nil, nil, ErrPlatformSignature
	}
	return platformPub, platformNonce, nil
}
