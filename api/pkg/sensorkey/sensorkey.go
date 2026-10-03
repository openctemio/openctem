// Package sensorkey builds and checks OpenCTEM sensor credentials.
//
// Design: docs/rfcs/RFC-032-sensor-enrollment-and-identity.md (revision
// 2026-10-03) and docs/architecture/agent-identity.md, "Credential formats".
//
// A token is
//
//	<prefix><random><checksum>
//
// where random is 32 bytes from crypto/rand written as exactly RandomLen
// base62 characters (zero-padded), and checksum is the CRC32 (IEEE) of the
// random part written as exactly ChecksumLen base62 characters. The style is
// GitHub's ghp_ tokens: a distinctive prefix, high entropy, and a checksum a
// secret scanner (or this API) can verify offline.
//
// The checksum is NOT a security control. Anyone can compute a CRC32; it only
// lets scanners match with near-zero false positives and lets the API turn
// away a mistyped or truncated key without a database lookup.
//
// Prefixes never start with "oct_": the HTTP layer routes "oct_" bearer tokens
// to user / MCP API-key authentication (middleware/apikey_auth.go).
package sensorkey

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash/crc32"
	"math/big"
	"strings"
)

const (
	// PrefixSensorKey is the prefix of a sensor API key.
	PrefixSensorKey = "octs_"
	// PrefixEnrollmentToken is the prefix of a one-time sensor enrollment
	// token (RFC-032 §6.2). Not issued yet; reserved so scanners and the
	// sensor authenticator already know it.
	PrefixEnrollmentToken = "octe_"
	// PrefixLegacySensorKey is the prefix of the sensor keys issued before
	// octs_: "rda_" + 64 hex characters, no checksum. Still accepted until
	// the sunset (90 days after enrollment and key-bound identity ship).
	PrefixLegacySensorKey = "rda_"

	// RandomBytes is the entropy of a token.
	RandomBytes = 32
	// RandomLen is the width of the random part: 32 bytes in base62.
	RandomLen = 43
	// ChecksumLen is the width of the checksum: a CRC32 in base62.
	ChecksumLen = 6
	// DisplayPrefixLen is how much of a key is stored and shown to identify
	// it: the 5-character prefix plus 5 random characters (about 30 bits, no
	// more than the 8 hex characters a legacy rda_ display prefix showed).
	// It fits the VARCHAR(12) prefix columns.
	DisplayPrefixLen = 10
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// prefixes are the checksummed formats this package issues and validates.
var prefixes = []string{PrefixSensorKey, PrefixEnrollmentToken}

// ErrUnknownPrefix is returned by New for a prefix this package does not issue.
var ErrUnknownPrefix = errors.New("sensorkey: unknown prefix")

// New returns a fresh token with the given prefix (PrefixSensorKey or
// PrefixEnrollmentToken).
func New(prefix string) (string, error) {
	if !isIssuedPrefix(prefix) {
		return "", ErrUnknownPrefix
	}
	b := make([]byte, RandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	random := encodeBase62(new(big.Int).SetBytes(b), RandomLen)
	return prefix + random + checksum(random), nil
}

// Valid reports whether token is a well-formed checksummed token and returns
// its prefix. A legacy rda_ key has no checksum and is never Valid; see
// IsLegacy.
func Valid(token string) (prefix string, ok bool) {
	for _, p := range prefixes {
		if !strings.HasPrefix(token, p) {
			continue
		}
		body := token[len(p):]
		if len(body) != RandomLen+ChecksumLen || !isBase62(body) {
			return "", false
		}
		random, sum := body[:RandomLen], body[RandomLen:]
		if subtle.ConstantTimeCompare([]byte(checksum(random)), []byte(sum)) != 1 {
			return "", false
		}
		return p, true
	}
	return "", false
}

// IsLegacy reports whether a key, or a stored display prefix, is a legacy
// rda_ sensor key.
func IsLegacy(keyOrPrefix string) bool {
	return strings.HasPrefix(keyOrPrefix, PrefixLegacySensorKey)
}

// AcceptableSensorKey is the offline check run before a presented sensor key
// is hashed and looked up. An octs_ key must be Valid; an octe_ enrollment
// token is never a sensor key; anything else (legacy rda_ keys) passes on to
// the lookup unchanged.
func AcceptableSensorKey(key string) bool {
	switch {
	case strings.HasPrefix(key, PrefixSensorKey):
		p, ok := Valid(key)
		return ok && p == PrefixSensorKey
	case strings.HasPrefix(key, PrefixEnrollmentToken):
		return false
	default:
		return true
	}
}

// DisplayPrefix returns the part of a token that is stored and shown to
// identify it (DisplayPrefixLen characters).
func DisplayPrefix(token string) string {
	if len(token) <= DisplayPrefixLen {
		return token
	}
	return token[:DisplayPrefixLen]
}

func isIssuedPrefix(p string) bool {
	for _, q := range prefixes {
		if p == q {
			return true
		}
	}
	return false
}

func checksum(random string) string {
	return encodeBase62(new(big.Int).SetUint64(uint64(crc32.ChecksumIEEE([]byte(random)))), ChecksumLen)
}

// encodeBase62 writes n in base62, left-padded with '0' to exactly width
// characters. Callers pass a width that always fits n.
func encodeBase62(n *big.Int, width int) string {
	out := make([]byte, width)
	for i := range out {
		out[i] = '0'
	}
	base := big.NewInt(62)
	mod := new(big.Int)
	v := new(big.Int).Set(n)
	for i := width - 1; i >= 0 && v.Sign() > 0; i-- {
		v.DivMod(v, base, mod)
		out[i] = alphabet[mod.Int64()]
	}
	return string(out)
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
