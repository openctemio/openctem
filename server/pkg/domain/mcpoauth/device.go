package mcpoauth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The device authorization grant (RFC 8628) for terminals without a browser
// on the same machine. Design: docs/rfcs/RFC-062-mcp-authorization.md.

const (
	// DeviceCodePrefix starts every device code, the secret a terminal polls
	// the token endpoint with; the rest is 256 random bits.
	DeviceCodePrefix = "octm_dc_"
	// DeviceClientID is the platform's terminal client: the client_id a
	// terminal uses for the device grant when its organization registered
	// none. A device request proves nothing about which program asks, so the
	// consent page never calls it verified.
	DeviceClientID = "octc_terminal"
	// DeviceRequestTTL is how long a device code and its user code live:
	// long enough to open a browser and sign in, short enough that a code
	// sent to someone else goes stale quickly.
	DeviceRequestTTL = RequestTTL
	// DevicePollInterval is the least time between two polls (RFC 8628 §3.2).
	DevicePollInterval = 5 * time.Second
	// DeviceSlowDownStep is added to the interval on every early poll
	// (RFC 8628 §3.5).
	DeviceSlowDownStep = 5 * time.Second
	// DeviceMaxPollInterval caps the interval an over-eager client earns.
	DeviceMaxPollInterval = 60 * time.Second
	// DeviceGrantType is the token endpoint grant_type of the device grant.
	DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// userCodeAlphabet is RFC 8628 §6.1's base-20 set: consonants only, no
// vowels (no words) and no characters people confuse.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLength is the number of characters of a user code: 20^8 is about
// 34.5 bits, with typing attempts limited per address and per person.
const UserCodeLength = 8

// NewUserCode returns a random user code, shown as XXXX-XXXX.
func NewUserCode() (string, error) {
	b := make([]byte, UserCodeLength)
	n := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("random user code: %w", err)
		}
		b[i] = userCodeAlphabet[v.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}

// NormalizeUserCode turns what a person typed into the canonical code:
// upper case, separators and spaces dropped. It returns "" when the result
// is not UserCodeLength characters of the alphabet.
func NormalizeUserCode(in string) string {
	if len(in) > 32 {
		return ""
	}
	var sb strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case strings.ContainsRune(userCodeAlphabet, r):
			sb.WriteRune(r)
		default:
			return ""
		}
	}
	if sb.Len() != UserCodeLength {
		return ""
	}
	return sb.String()
}
