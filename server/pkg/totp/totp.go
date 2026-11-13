// Package totp implements time-based one-time passwords (RFC 6238, built on
// the HOTP algorithm of RFC 4226) with the parameters every authenticator app
// supports by default: HMAC-SHA1, 6 digits, 30-second steps.
//
// It is implemented here rather than pulled in as a dependency because it is
// small, fully specified by the RFCs, and sits on the admin authentication path
// where an auditable implementation matters more than convenience. The tests
// check it against the RFC 6238 Appendix B vectors.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA1 is not affected by SHA-1 collisions.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the code length.
	Digits = 6
	// Period is the step length.
	Period = 30 * time.Second
	// Skew is how many steps before/after the current one are accepted, to
	// absorb clock drift between the server and the authenticator.
	Skew = 1
	// secretBytes is the secret length (160 bits, the RFC 4226 recommendation).
	secretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random secret, base32-encoded without padding
// (the form authenticator apps expect).
func GenerateSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return b32.EncodeToString(buf), nil
}

// Step returns the RFC 6238 time step for t.
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// codeAt computes the HOTP value (RFC 4226 section 5.3) for a raw key and step.
func codeAt(key []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step is a positive Unix-time counter.
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := b32.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid totp secret: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("invalid totp secret: empty")
	}
	return key, nil
}

// Code returns the 6-digit code for secret at time t.
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return codeAt(key, Step(t), Digits), nil
}

// Verify checks code against secret at time t, accepting ±Skew steps. It
// returns the matched step so callers can reject replays: a caller should
// accept a code only if the returned step is greater than the last step it
// accepted for this secret. All candidate steps are compared in constant time.
func Verify(secret, code string, t time.Time) (step int64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	now := Step(t)
	var matched int64
	found := 0
	for delta := int64(-Skew); delta <= Skew; delta++ {
		candidate := codeAt(key, now+delta, Digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			// Keep the latest matching step so replay protection is strictest.
			matched = now + delta
			found = 1
		}
	}
	return matched, found == 1
}

// URI returns the otpauth:// provisioning URI shown as a QR code by
// authenticator apps.
func URI(secret, issuer, account string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
