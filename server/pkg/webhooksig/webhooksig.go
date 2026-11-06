// Package webhooksig signs and verifies outbound webhook deliveries in the
// Standard Webhooks format (docs/rfcs/RFC-124-outbound-webhooks.md):
//
//	webhook-id:        <message id, stable across retries>
//	webhook-timestamp: <unix seconds>
//	webhook-signature: v1,<base64 HMAC-SHA256(key, id + "." + timestamp + "." + body)>
//
// The secret is "whsec_" + base64(key). During a rotation overlap the header
// carries one space-separated signature per valid secret; a receiver accepts
// the delivery when any of them verifies.
package webhooksig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Header names.
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
)

// SecretPrefix starts every secret.
const SecretPrefix = "whsec_"

// secretBytes is the key length of a generated secret (256 bits).
const secretBytes = 32

// DefaultTolerance is how far a delivery's timestamp may be from the
// receiver's clock: the replay window.
const DefaultTolerance = 5 * time.Minute

// Errors of Verify. ErrNoMatch and ErrTimestamp are distinct so a receiver
// can log which check refused a delivery.
var (
	ErrSecret    = errors.New("webhooksig: malformed secret")
	ErrHeaders   = errors.New("webhooksig: missing or malformed headers")
	ErrTimestamp = errors.New("webhooksig: timestamp outside the tolerance")
	ErrNoMatch   = errors.New("webhooksig: no matching signature")
)

// GenerateSecret returns a new random secret.
func GenerateSecret() (string, error) {
	key := make([]byte, secretBytes)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	return SecretPrefix + base64.StdEncoding.EncodeToString(key), nil
}

// ParseSecret returns the key of a secret ("whsec_" + base64).
func ParseSecret(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, SecretPrefix) {
		return nil, ErrSecret
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, SecretPrefix))
	if err != nil || len(key) < 16 {
		return nil, ErrSecret
	}
	return key, nil
}

// Sign returns the base64 signature of one delivery under one key.
func Sign(key []byte, id string, ts time.Time, body []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(id + "." + strconv.FormatInt(ts.Unix(), 10) + "."))
	_, _ = m.Write(body)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Headers returns the three headers of a delivery signed with every secret
// given (the current one first, then one still in its rotation overlap).
func Headers(id string, ts time.Time, body []byte, secrets ...string) (map[string]string, error) {
	if id == "" || len(secrets) == 0 {
		return nil, ErrHeaders
	}
	sigs := make([]string, 0, len(secrets))
	for _, s := range secrets {
		key, err := ParseSecret(s)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, "v1,"+Sign(key, id, ts, body))
	}
	return map[string]string{
		HeaderID:        id,
		HeaderTimestamp: strconv.FormatInt(ts.Unix(), 10),
		HeaderSignature: strings.Join(sigs, " "),
	}, nil
}

// Verify is the reference receiver check: the timestamp is within tolerance
// of now, and one v1 signature in the header matches the body under secret
// (compared in constant time). get reads a request header.
func Verify(secret string, get func(string) string, body []byte, now time.Time, tolerance time.Duration) error {
	key, err := ParseSecret(secret)
	if err != nil {
		return err
	}
	id, tsRaw, sigHeader := get(HeaderID), get(HeaderTimestamp), get(HeaderSignature)
	if id == "" || tsRaw == "" || sigHeader == "" {
		return ErrHeaders
	}
	sec, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return ErrHeaders
	}
	ts := time.Unix(sec, 0)
	if math.Abs(float64(now.Sub(ts))) > float64(tolerance) {
		return ErrTimestamp
	}
	want := []byte(Sign(key, id, ts, body))
	for _, part := range strings.Fields(sigHeader) {
		version, sig, ok := strings.Cut(part, ",")
		if !ok || version != "v1" {
			continue
		}
		if hmac.Equal([]byte(sig), want) {
			return nil
		}
	}
	return ErrNoMatch
}
