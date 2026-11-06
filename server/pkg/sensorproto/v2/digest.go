package v2

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"strings"
)

// Content-Digest (RFC 9530). The digest covers the content as sent, i.e. the
// compressed bytes when Content-Encoding is set (RFC 9530 §2), so the server
// verifies it before anything is decompressed.

// Digest algorithms the server verifies (RFC 9530 §5, "active").
const (
	DigestSHA256 = "sha-256"
	DigestSHA512 = "sha-512"
)

var (
	// ErrDigestMissing: no Content-Digest, or none with a supported algorithm.
	ErrDigestMissing = errors.New("content digest missing")
	// ErrDigestMalformed: the header is not a structured-field dictionary of
	// byte sequences, or a supported algorithm has the wrong length.
	ErrDigestMalformed = errors.New("content digest malformed")
)

// Digests are the supported digests a request declared, by algorithm.
type Digests map[string][]byte

// ParseContentDigest parses the Content-Digest header values. Members with an
// algorithm the server does not verify are ignored, as RFC 9530 §2 allows; a
// header that names none it verifies is ErrDigestMissing. The parser accepts
// only what an RFC 8941 dictionary of byte sequences can be: lower-case keys,
// ":base64:" values, no parameters.
func ParseContentDigest(values []string) (Digests, error) {
	out := Digests{}
	seen := map[string]bool{}
	for _, header := range values {
		for _, member := range strings.Split(header, ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				return nil, ErrDigestMalformed
			}
			key, val, ok := strings.Cut(member, "=")
			if !ok || !validDigestKey(key) {
				return nil, ErrDigestMalformed
			}
			if seen[key] {
				// RFC 8941 keeps the last duplicate; a digest header with two
				// different values for one algorithm is ambiguous. Refuse it.
				return nil, ErrDigestMalformed
			}
			seen[key] = true
			if len(val) < 2 || val[0] != ':' || val[len(val)-1] != ':' {
				return nil, ErrDigestMalformed
			}
			sum, err := base64.StdEncoding.Strict().DecodeString(val[1 : len(val)-1])
			if err != nil {
				return nil, ErrDigestMalformed
			}
			switch key {
			case DigestSHA256:
				if len(sum) != sha256.Size {
					return nil, ErrDigestMalformed
				}
				out[key] = sum
			case DigestSHA512:
				if len(sum) != sha512.Size {
					return nil, ErrDigestMalformed
				}
				out[key] = sum
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrDigestMissing
	}
	return out, nil
}

// validDigestKey is the RFC 8941 key grammar: lcalpha / "*" then
// lcalpha / DIGIT / "_" / "-" / "." / "*".
func validDigestKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c == '*':
		case i > 0 && (c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// NewDigestHashes returns a hash per algorithm the request declared, for a
// reader to feed while it reads the body once.
func (d Digests) NewDigestHashes() map[string]hash.Hash {
	hs := make(map[string]hash.Hash, len(d))
	for alg := range d {
		switch alg {
		case DigestSHA256:
			hs[alg] = sha256.New()
		case DigestSHA512:
			hs[alg] = sha512.New()
		}
	}
	return hs
}

// FormatSHA256 renders a SHA-256 sum as a Content-Digest member. It is the
// canonical, stored fingerprint of a segment: the server always computes the
// SHA-256 of the received bytes, whatever algorithm the sensor declared.
func FormatSHA256(sum []byte) string {
	return DigestSHA256 + "=:" + base64.StdEncoding.EncodeToString(sum) + ":"
}

// CanonicalSHA256 extracts the sha-256 member of a Content-Digest value in the
// canonical form FormatSHA256 produces, for comparing the digests a commit
// lists with the stored ones. ok is false when the value has no valid sha-256.
func CanonicalSHA256(value string) (string, bool) {
	d, err := ParseContentDigest([]string{value})
	if err != nil {
		return "", false
	}
	sum, ok := d[DigestSHA256]
	if !ok {
		return "", false
	}
	return FormatSHA256(sum), true
}
