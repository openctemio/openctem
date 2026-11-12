package aimask

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnknownToken is returned by UnmaskStrict when the text holds a token the
// run never issued (forged, invented by the model, or another run's).
var ErrUnknownToken = errors.New("aimask: unknown placeholder")

// ErrNotGranted is returned by ResolveForGrant for anything but a token
// bound in the grant.
var ErrNotGranted = errors.New("aimask: placeholder not bound in the grant")

// UnknownToken is a token-shaped string in output that does not resolve.
type UnknownToken struct {
	Token string `json:"token"`
}

// Unmasker turns model output back into real values. It is built from a
// run's stored snapshot (or from the live masker).
type Unmasker struct {
	tokens      map[string]string
	secretCount int
}

// NewUnmasker builds an unmasker from a stored snapshot.
func NewUnmasker(s Snapshot) *Unmasker {
	t := make(map[string]string, len(s.Tokens))
	for k, v := range s.Tokens {
		t[k] = v
	}
	return &Unmasker{tokens: t, secretCount: s.SecretCount}
}

// Unmasker returns the unmasker of this masker's run.
func (m *Masker) Unmasker() *Unmasker { return NewUnmasker(m.Snapshot()) }

// Unmask replaces every issued token in text with its value. SECRET_n stays
// as it is (secrets are never resolved). A token the run never issued stays
// visible as text and is reported, so the caller can mark the result for a
// person's review and never act on it.
func (u *Unmasker) Unmask(text string) (string, []UnknownToken) {
	var unknown []UnknownToken
	seen := map[string]bool{}
	out := tokenShapeRE.ReplaceAllStringFunc(text, func(tok string) string {
		if !tokenCandidate(tok) {
			return tok
		}
		if v, ok := u.tokens[tok]; ok {
			return v
		}
		if n, ok := secretIndex(tok); ok && n >= 1 && n <= u.secretCount {
			return tok
		}
		if !seen[tok] {
			seen[tok] = true
			unknown = append(unknown, UnknownToken{Token: tok})
		}
		return tok
	})
	return out, unknown
}

// UnmaskStrict is Unmask for a typed field that must hold real values: any
// unknown token is an error and nothing is returned.
func (u *Unmasker) UnmaskStrict(text string) (string, error) {
	out, unknown := u.Unmask(text)
	if len(unknown) > 0 {
		return "", fmt.Errorf("%w: %s", ErrUnknownToken, unknown[0].Token)
	}
	return out, nil
}

func secretIndex(tok string) (int, bool) {
	if !strings.HasPrefix(tok, "SECRET_") {
		return 0, false
	}
	n, err := strconv.Atoi(tok[len("SECRET_"):])
	return n, err == nil
}

// ResolveForGrant is the tool boundary's lookup: the real target for a
// masked target the model passed (a token, or labels in front of a domain
// token) when the investigation grant binds exactly that form, otherwise
// ErrNotGranted. A raw value, another host under the same domain token, a
// token of another run, a secret or a literal never resolves.
func ResolveForGrant(bindings []Binding, masked string) (string, error) {
	if masked == "" || strings.ContainsAny(masked, " \t\r\n/:@?#") {
		return "", ErrNotGranted
	}
	toks := issuedTokenRE.FindAllString(masked, -1)
	if len(toks) != 1 || !strings.HasSuffix(masked, toks[0]) {
		return "", ErrNotGranted
	}
	if strings.HasPrefix(toks[0], "SECRET_") || strings.HasPrefix(toks[0], "LIT_") {
		return "", ErrNotGranted
	}
	for _, b := range bindings {
		if b.Token == masked && b.Value != "" {
			return b.Value, nil
		}
	}
	return "", ErrNotGranted
}
