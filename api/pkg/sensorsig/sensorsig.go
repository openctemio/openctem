// Package sensorsig is the HTTP message signature profile a key-bound sensor
// uses on every platform request (api RFC-032 E5, api RFC-052): RFC 9421
// signatures with the sensor's Ed25519 key and an RFC 9530 Content-Digest
// over the body. No bearer secret travels; a captured request is useless
// after its nonce is spent or its window closes.
//
// The profile is deliberately narrow so both sides implement it the same
// way and a verifier can refuse everything else:
//
//   - one signature, label "sig1";
//   - covered components, in this order: "@method" "@path" "@query", and
//     "content-digest" when the request has a body;
//   - parameters, in this order: created, expires, nonce, keyid,
//     alg="ed25519", tag="openctem-sensor/v1";
//   - keyid is the RFC 7638 JWK thumbprint of the Ed25519 public key;
//   - expires - created is at most MaxWindow; the verifier allows
//     MaxClockSkew between the clocks;
//   - Content-Digest carries sha-256 only.
//
// The host is not covered: TLS terminating gateways rewrite it, and the
// platform's own URL is configuration on both sides. The path is covered as
// the client dialed it, so a gateway in front of the API must not rewrite
// paths.
//
// The same profile is implemented in sdk-go pkg/sensorsig; the shared test
// vectors (pkg/sensorproto/pairing/testdata/vectors.json) pin both.
package sensorsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Profile constants.
const (
	// Label is the signature label in Signature-Input and Signature.
	Label = "sig1"
	// Tag is the application tag every signature carries.
	Tag = "openctem-sensor/v1"
	// Alg is the only algorithm.
	Alg = "ed25519"
	// MaxWindow is the longest validity a signature may claim.
	MaxWindow = 5 * time.Minute
	// DefaultWindow is the validity the signer gives a request.
	DefaultWindow = 2 * time.Minute
	// MaxClockSkew is how far created may lie in the future, and how far
	// expires may lie in the past, for the verifier to accept it.
	MaxClockSkew = 2 * time.Minute
	// MinNonceLength and MaxNonceLength bound the nonce.
	MinNonceLength = 16
	MaxNonceLength = 64
	// MaxHeaderLength bounds Signature-Input and Signature.
	MaxHeaderLength = 1024

	// HeaderSignatureInput, HeaderSignature and HeaderContentDigest are
	// the header names.
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"
	HeaderContentDigest  = "Content-Digest"
)

// Errors a verifier returns. Every one means "refuse the request"; callers
// answer them all with the same unauthenticated response.
var (
	ErrMissing       = errors.New("sensorsig: no signature")
	ErrMalformed     = errors.New("sensorsig: malformed signature headers")
	ErrProfile       = errors.New("sensorsig: signature outside the profile")
	ErrExpired       = errors.New("sensorsig: signature outside its validity window")
	ErrBadSignature  = errors.New("sensorsig: signature does not verify")
	ErrDigest        = errors.New("sensorsig: content digest missing or wrong")
	ErrUnknownKey    = errors.New("sensorsig: unknown key")
	ErrReplayed      = errors.New("sensorsig: nonce already used")
	ErrBodyTooLarge  = errors.New("sensorsig: body too large to verify")
	errNoPrivateKey  = errors.New("sensorsig: no private key")
	coveredNoBody    = []string{"@method", "@path", "@query"}
	coveredWithBody  = []string{"@method", "@path", "@query", "content-digest"}
	b64              = base64.StdEncoding
	b64url           = base64.RawURLEncoding
	errNonceReadFail = errors.New("sensorsig: cannot read random nonce")
)

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key
// (base64url, no padding): the keyid of every signature and the key's
// fingerprint everywhere it is shown.
func Thumbprint(pub ed25519.PublicKey) string {
	// RFC 7638 §3.2: required members only, lexicographic order, no
	// whitespace. For OKP keys these are crv, kty and x (RFC 8037 §2).
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + b64url.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return b64url.EncodeToString(sum[:])
}

// ContentDigest is the RFC 9530 Content-Digest field value of body
// ("sha-256=:<base64>:").
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + b64.EncodeToString(sum[:]) + ":"
}

// VerifyContentDigest checks that header is exactly the sha-256
// Content-Digest of body.
func VerifyContentDigest(header string, body []byte) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return ErrDigest
	}
	want := ContentDigest(body)
	if subtle.ConstantTimeCompare([]byte(header), []byte(want)) != 1 {
		return ErrDigest
	}
	return nil
}

// Params are the signature parameters of one request.
type Params struct {
	Created time.Time
	Expires time.Time
	Nonce   string
	KeyID   string
}

// Components are the request values the signature covers.
type Components struct {
	Method string
	// Path is the request path as sent (escaped).
	Path string
	// RawQuery is the query without the leading "?".
	RawQuery string
	// ContentDigest is the Content-Digest value; empty when the request
	// has no body.
	ContentDigest string
}

// ComponentsOf reads the covered components from r.
func ComponentsOf(r *http.Request) Components {
	return Components{
		Method:        strings.ToUpper(r.Method),
		Path:          r.URL.EscapedPath(),
		RawQuery:      r.URL.RawQuery,
		ContentDigest: strings.TrimSpace(r.Header.Get(HeaderContentDigest)),
	}
}

// SignatureParams is the @signature-params value (the Signature-Input
// member without its label).
func SignatureParams(c Components, p Params) string {
	covered := coveredNoBody
	if c.ContentDigest != "" {
		covered = coveredWithBody
	}
	var b strings.Builder
	b.WriteByte('(')
	for i, name := range covered {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.Quote(name))
	}
	b.WriteByte(')')
	fmt.Fprintf(&b, ";created=%d;expires=%d;nonce=%q;keyid=%q;alg=%q;tag=%q",
		p.Created.Unix(), p.Expires.Unix(), p.Nonce, p.KeyID, Alg, Tag)
	return b.String()
}

// SignatureBase is the RFC 9421 §2.5 signature base for c under p.
func SignatureBase(c Components, p Params) string {
	query := "?" + c.RawQuery
	var b strings.Builder
	fmt.Fprintf(&b, "\"@method\": %s\n", c.Method)
	fmt.Fprintf(&b, "\"@path\": %s\n", c.Path)
	fmt.Fprintf(&b, "\"@query\": %s\n", query)
	if c.ContentDigest != "" {
		fmt.Fprintf(&b, "\"content-digest\": %s\n", c.ContentDigest)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", SignatureParams(c, p))
	return b.String()
}

// Signer signs requests with one sensor key.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
	// Now and Nonce are replaceable for tests.
	Now   func() time.Time
	Nonce func() (string, error)
	// Window is the validity of each signature (default DefaultWindow,
	// at most MaxWindow).
	Window time.Duration
}

// NewSigner returns a signer for key.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errNoPrivateKey
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Signer{key: key, keyID: Thumbprint(pub), Now: time.Now, Nonce: RandomNonce}, nil
}

// KeyID is the signer's keyid (the key's thumbprint).
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey is the signer's public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return pub
}

// SignBytes signs msg with the key (for the pairing transcripts).
func (s *Signer) SignBytes(msg []byte) []byte { return ed25519.Sign(s.key, msg) }

// RandomNonce is 24 random bytes in base64url (32 characters).
func RandomNonce() (string, error) {
	var n [24]byte
	if _, err := rand.Read(n[:]); err != nil {
		return "", errNonceReadFail
	}
	return b64url.EncodeToString(n[:]), nil
}

// Sign sets Content-Digest (when body is not empty), Signature-Input and
// Signature on r. body must be the exact bytes r will send.
func (s *Signer) Sign(r *http.Request, body []byte) error {
	now := s.Now()
	window := s.Window
	if window <= 0 || window > MaxWindow {
		window = DefaultWindow
	}
	nonce, err := s.Nonce()
	if err != nil {
		return err
	}
	if len(body) > 0 {
		r.Header.Set(HeaderContentDigest, ContentDigest(body))
	} else {
		r.Header.Del(HeaderContentDigest)
	}
	p := Params{Created: now, Expires: now.Add(window), Nonce: nonce, KeyID: s.keyID}
	c := ComponentsOf(r)
	sig := ed25519.Sign(s.key, []byte(SignatureBase(c, p)))
	r.Header.Set(HeaderSignatureInput, Label+"="+SignatureParams(c, p))
	r.Header.Set(HeaderSignature, Label+"=:"+b64.EncodeToString(sig)+":")
	return nil
}

// Transport signs every request it carries and removes any bearer
// credential, so a key-bound sensor never sends one.
type Transport struct {
	Signer *Signer
	// Base is the transport that sends the signed request
	// (http.DefaultTransport when nil).
	Base http.RoundTripper
	// MaxBody bounds the body it reads to sign (default 128 MiB).
	MaxBody int64
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	limit := t.MaxBody
	if limit <= 0 {
		limit = 128 << 20
	}
	out := req.Clone(req.Context())
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, ErrBodyTooLarge
		}
		body = b
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	out.Header.Del("Authorization")
	out.Header.Del("X-API-Key")
	if err := t.Signer.Sign(out, body); err != nil {
		return nil, err
	}
	return base.RoundTrip(out)
}

// Parsed is a Signature-Input / Signature pair inside the profile.
type Parsed struct {
	Params     Params
	Covered    []string
	Signature  []byte
	paramsText string
}

// Parse reads and checks the signature headers of h against the profile.
// It does not verify the signature or the time window.
func Parse(h http.Header) (*Parsed, error) {
	inputs, sigs := h.Values(HeaderSignatureInput), h.Values(HeaderSignature)
	if len(inputs) == 0 && len(sigs) == 0 {
		return nil, ErrMissing
	}
	if len(inputs) != 1 || len(sigs) != 1 {
		return nil, ErrMalformed
	}
	input, sig := strings.TrimSpace(inputs[0]), strings.TrimSpace(sigs[0])
	if len(input) > MaxHeaderLength || len(sig) > MaxHeaderLength {
		return nil, ErrMalformed
	}
	paramsText, ok := strings.CutPrefix(input, Label+"=")
	if !ok {
		return nil, ErrProfile
	}
	sigText, ok := strings.CutPrefix(sig, Label+"=:")
	if !ok || !strings.HasSuffix(sigText, ":") {
		return nil, ErrMalformed
	}
	rawSig, err := b64.DecodeString(strings.TrimSuffix(sigText, ":"))
	if err != nil || len(rawSig) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	covered, rest, err := parseInnerList(paramsText)
	if err != nil {
		return nil, err
	}
	p, err := parseParams(rest)
	if err != nil {
		return nil, err
	}
	out := &Parsed{Params: p, Covered: covered, Signature: rawSig, paramsText: paramsText}
	// The profile fixes the text exactly: re-serialize and compare, so no
	// whitespace, ordering or encoding variant passes.
	c := Components{}
	if len(covered) == len(coveredWithBody) {
		c.ContentDigest = "x"
	}
	if SignatureParams(c, p) != paramsText {
		return nil, ErrProfile
	}
	return out, nil
}

func parseInnerList(s string) ([]string, string, error) {
	if !strings.HasPrefix(s, "(") {
		return nil, "", ErrProfile
	}
	end := strings.IndexByte(s, ')')
	if end < 0 {
		return nil, "", ErrMalformed
	}
	covered := make([]string, 0, len(coveredWithBody))
	for _, item := range strings.Fields(s[1:end]) {
		name, err := strconv.Unquote(item)
		if err != nil {
			return nil, "", ErrMalformed
		}
		covered = append(covered, name)
	}
	if !equalStrings(covered, coveredNoBody) && !equalStrings(covered, coveredWithBody) {
		return nil, "", ErrProfile
	}
	return covered, s[end+1:], nil
}

func parseParams(s string) (Params, error) {
	var p Params
	seen := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(s, ";"), ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok || name == "" {
			return Params{}, ErrMalformed
		}
		if _, dup := seen[name]; dup {
			return Params{}, ErrProfile
		}
		seen[name] = value
	}
	if len(seen) != 6 {
		return Params{}, ErrProfile
	}
	created, err1 := strconv.ParseInt(seen["created"], 10, 64)
	expires, err2 := strconv.ParseInt(seen["expires"], 10, 64)
	if err1 != nil || err2 != nil {
		return Params{}, ErrMalformed
	}
	str := func(name string) (string, error) {
		v, err := strconv.Unquote(seen[name])
		if err != nil || !strings.HasPrefix(seen[name], `"`) {
			return "", ErrMalformed
		}
		return v, nil
	}
	nonce, err := str("nonce")
	if err != nil {
		return Params{}, err
	}
	keyID, err := str("keyid")
	if err != nil {
		return Params{}, err
	}
	alg, err := str("alg")
	if err != nil {
		return Params{}, err
	}
	tag, err := str("tag")
	if err != nil {
		return Params{}, err
	}
	if alg != Alg || tag != Tag || !tokenLike(nonce, MinNonceLength, MaxNonceLength) || !tokenLike(keyID, 43, 43) {
		return Params{}, ErrProfile
	}
	p.Created, p.Expires, p.Nonce, p.KeyID = time.Unix(created, 0), time.Unix(expires, 0), nonce, keyID
	return p, nil
}

// tokenLike reports whether s is base64url-alphabet text of a bounded length.
func tokenLike(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// CoversDigest reports whether the signature covers Content-Digest.
func (p *Parsed) CoversDigest() bool { return len(p.Covered) == len(coveredWithBody) }

// CheckWindow checks created/expires against now.
func (p *Parsed) CheckWindow(now time.Time) error {
	c, e := p.Params.Created, p.Params.Expires
	if !e.After(c) || e.Sub(c) > MaxWindow {
		return ErrProfile
	}
	if c.After(now.Add(MaxClockSkew)) || now.After(e.Add(MaxClockSkew)) {
		return ErrExpired
	}
	return nil
}

// Verify checks the signature over r's components with pub. It does not
// check the body against Content-Digest (VerifyContentDigest), the window
// (CheckWindow) or the nonce: the caller does those.
func (p *Parsed) Verify(r *http.Request, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize || Thumbprint(pub) != p.Params.KeyID {
		return ErrUnknownKey
	}
	c := ComponentsOf(r)
	if len(r.Header.Values(HeaderContentDigest)) > 1 {
		return ErrMalformed
	}
	hasDigest := p.CoversDigest()
	if hasDigest != (c.ContentDigest != "") {
		return ErrProfile
	}
	if !ed25519.Verify(pub, []byte(SignatureBase(c, p.Params)), p.Signature) {
		return ErrBadSignature
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
