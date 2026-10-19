// Package sealed is the platform's implementation of the end-to-end
// envelope a sensor and the platform exchange through an intermediary they
// do not trust: the sensor relay, later an object store. Design:
// docs/rfcs/RFC-116-sensor-relay.md. The sensor side lives in sdk-go
// (pkg/sealedmsg); both implementations are checked against the same test
// vector (testdata/vector-v1.json), since the platform depends on
// contracts only (RFC-094).
//
// A request is the sensor's ordinary signed v2 request (method, path,
// headers including the RFC 9421 signature, body), sealed with HPKE (RFC
// 9180) to the platform's ingest key. A response is signed by the
// platform's response key, bound to the digest of the request envelope it
// answers, and sealed to the sensor's encryption key. An intermediary can
// delay or drop envelopes; it cannot read them, change them, swap a
// response between requests or sensors, or send one in the platform's
// name. Replays of a request are refused by the platform's RFC 9421 nonce
// check, as for a direct request; a response opens only for the request it
// names.
//
// Wire format, version 1:
//
//	magic   4 bytes  "OCSE"
//	version 1 byte   0x01
//	kind    1 byte   0x01 request, 0x02 response
//	suite   2 bytes  0x0001: KEM ML-KEM-768+X25519, KDF HKDF-SHA256,
//	                 AEAD ChaCha20-Poly1305
//	key id  16 bytes first 16 bytes of SHA-256 of the recipient public key
//	sealed  HPKE base-mode single-shot output (encapsulated key || ciphertext)
//
//	info = "openctem-sealed/v1" 0x00 || the 24 header bytes ||
//	       u16 len || realm || u16 len || sensor id
//
// The header and the route (realm, sensor) are bound through the HPKE info:
// an envelope moved to another sensor's mailbox, or relabeled, does not
// open.
//
// Plaintext of a request:  u32 len || meta JSON (RequestMeta) || body.
// Plaintext of a response: u32 len || meta JSON (ResponseMeta) || body ||
// Ed25519 signature (64 bytes) over
// "openctem-sealed-response/v1" 0x00 || everything before the signature.
package sealed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Kinds.
const (
	KindRequest  byte = 0x01
	KindResponse byte = 0x02
)

// Suite is the algorithm suite of an envelope.
const SuiteHybridV1 uint16 = 0x0001

// Limits.
const (
	// MaxBody bounds the body of one envelope (the v2 request body cap).
	MaxBody = 16 << 20
	// MaxEnvelope bounds one envelope on the wire.
	MaxEnvelope = MaxBody + 64<<10
	// MaxMeta bounds the meta JSON.
	MaxMeta = 64 << 10
	// MaxHeaders bounds the header fields carried.
	MaxHeaders = 64
	// MaxResponseSkew is how far a response's issued_at may be from the
	// sensor's clock.
	MaxResponseSkew = 10 * time.Minute

	headerLen = 24
	keyIDLen  = 16
	magic     = "OCSE"
	version   = 1
	infoLabel = "openctem-sealed/v1"
	sigLabel  = "openctem-sealed-response/v1"
)

// Errors.
var (
	// ErrMalformed: not an envelope of this version, or a part out of
	// bounds.
	ErrMalformed = errors.New("sealed: malformed envelope")
	// ErrUnknownKey: the envelope is for a key this side does not hold.
	ErrUnknownKey = errors.New("sealed: envelope for an unknown key")
	// ErrOpen: the envelope does not open for this route and key (altered,
	// moved to another mailbox, or not for us).
	ErrOpen = errors.New("sealed: envelope does not open")
	// ErrSignature: a response not signed by a pinned response key.
	ErrSignature = errors.New("sealed: response signature not valid")
	// ErrBinding: a response for another request, sensor or realm, or out
	// of the time window.
	ErrBinding = errors.New("sealed: response does not answer this request")
)

func kem() hpke.KEM { return hpke.MLKEM768X25519() }

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

// PrivateKey is an encryption key pair (the sensor's, or the platform's
// ingest key).
type PrivateKey struct {
	k  hpke.PrivateKey
	id [keyIDLen]byte
}

// PublicKey is the public half others seal to.
type PublicKey struct {
	k  hpke.PublicKey
	id [keyIDLen]byte
}

func keyID(pub []byte) [keyIDLen]byte {
	sum := sha256.Sum256(pub)
	var id [keyIDLen]byte
	copy(id[:], sum[:keyIDLen])
	return id
}

// GenerateKey makes a new key pair.
func GenerateKey() (*PrivateKey, error) {
	k, err := kem().GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{k: k, id: keyID(k.PublicKey().Bytes())}, nil
}

// ParsePrivateKey reads a key pair from Bytes.
func ParsePrivateKey(b []byte) (*PrivateKey, error) {
	k, err := kem().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("sealed: private key: %w", err)
	}
	return &PrivateKey{k: k, id: keyID(k.PublicKey().Bytes())}, nil
}

// Bytes serializes the private key (keep it sealed: localstore).
func (k *PrivateKey) Bytes() ([]byte, error) { return k.k.Bytes() }

// Public returns the public key.
func (k *PrivateKey) Public() *PublicKey { return &PublicKey{k: k.k.PublicKey(), id: k.id} }

// KeyID is the hex key id.
func (k *PrivateKey) KeyID() string { return hex.EncodeToString(k.id[:]) }

// ParsePublicKey reads a public key from Bytes.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	p, err := kem().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("sealed: public key: %w", err)
	}
	return &PublicKey{k: p, id: keyID(p.Bytes())}, nil
}

// Bytes serializes the public key.
func (p *PublicKey) Bytes() []byte { return p.k.Bytes() }

// KeyID is the hex key id.
func (p *PublicKey) KeyID() string { return hex.EncodeToString(p.id[:]) }

// Route is who an envelope travels for: the platform realm (one platform
// installation or cell) and the sensor. Both sides know it from their own
// context (the sensor from its pairing, the platform from the mailbox the
// relay ticket names), never from the envelope.
type Route struct {
	Realm    string
	SensorID string
}

func (r Route) valid() error {
	if r.Realm == "" || r.SensorID == "" || len(r.Realm) > 256 || len(r.SensorID) > 256 {
		return fmt.Errorf("%w: route", ErrMalformed)
	}
	return nil
}

func header(kind byte, id [keyIDLen]byte) []byte {
	h := make([]byte, 0, headerLen)
	h = append(h, magic...)
	h = append(h, version, kind)
	h = binary.BigEndian.AppendUint16(h, SuiteHybridV1)
	return append(h, id[:]...)
}

func info(hdr []byte, r Route) []byte {
	out := make([]byte, 0, len(infoLabel)+1+len(hdr)+4+len(r.Realm)+len(r.SensorID))
	out = append(out, infoLabel...)
	out = append(out, 0)
	out = append(out, hdr...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Realm))) //nolint:gosec // bounded by valid()
	out = append(out, r.Realm...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.SensorID))) //nolint:gosec // bounded by valid()
	return append(out, r.SensorID...)
}

func sealTo(to *PublicKey, kind byte, r Route, pt []byte) ([]byte, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	hdr := header(kind, to.id)
	kdf, aead := suite()
	ct, err := hpke.Seal(to.k, kdf, aead, info(hdr, r), pt)
	if err != nil {
		return nil, fmt.Errorf("sealed: seal: %w", err)
	}
	if len(hdr)+len(ct) > MaxEnvelope {
		return nil, fmt.Errorf("%w: envelope too large", ErrMalformed)
	}
	return append(hdr, ct...), nil
}

// Header is what can be read from an envelope without opening it.
type Header struct {
	Kind  byte
	KeyID string
}

// PeekHeader parses an envelope's header (an intermediary never needs it;
// the platform uses it to pick the ingest key during a rotation).
func PeekHeader(env []byte) (Header, error) {
	if len(env) < headerLen || len(env) > MaxEnvelope || string(env[:4]) != magic || env[4] != version ||
		(env[5] != KindRequest && env[5] != KindResponse) || binary.BigEndian.Uint16(env[6:8]) != SuiteHybridV1 {
		return Header{}, ErrMalformed
	}
	return Header{Kind: env[5], KeyID: hex.EncodeToString(env[8:headerLen])}, nil
}

func openWith(keys []*PrivateKey, kind byte, r Route, env []byte) ([]byte, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	h, err := PeekHeader(env)
	if err != nil {
		return nil, err
	}
	if h.Kind != kind {
		return nil, ErrMalformed
	}
	var key *PrivateKey
	for _, k := range keys {
		if k != nil && subtle.ConstantTimeCompare(k.id[:], env[8:headerLen]) == 1 {
			key = k
		}
	}
	if key == nil {
		return nil, ErrUnknownKey
	}
	kdf, aead := suite()
	pt, err := hpke.Open(key.k, kdf, aead, info(env[:headerLen], r), env[headerLen:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Digest is the SHA-256 of an envelope: what a response is bound to.
func Digest(env []byte) [32]byte { return sha256.Sum256(env) }

// RequestMeta is the inner request without its body.
type RequestMeta struct {
	// ID is a random request id (hex); the sensor matches responses to
	// outstanding requests by the envelope digest, the id helps logs.
	ID     string      `json:"id"`
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Header http.Header `json:"header,omitempty"`
	// Created is when the sensor built the request (store-and-forward
	// windows are checked by the platform).
	Created time.Time `json:"created"`
	// ReplyKey is the sensor's encryption public key (PublicKey.Bytes):
	// the platform seals its answer to it. It travels inside the sealed
	// envelope, so only the sender chose it; the platform answers with
	// data only after the inner request's signature verified.
	ReplyKey []byte `json:"reply_key"`
}

// Request is an inner request.
type Request struct {
	RequestMeta
	Body []byte
}

// hopHeaders are never carried: they belong to one connection.
var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true, "Content-Length": true,
}

func cleanHeader(h http.Header) (http.Header, error) {
	out := http.Header{}
	n := 0
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		if hopHeaders[ck] {
			continue
		}
		for _, v := range vs {
			if n++; n > MaxHeaders {
				return nil, fmt.Errorf("%w: more than %d header fields", ErrMalformed, MaxHeaders)
			}
			if len(ck)+len(v) > 8<<10 || strings.ContainsAny(v, "\r\n\x00") || strings.ContainsAny(ck, "\r\n\x00: ") {
				return nil, fmt.Errorf("%w: header %q", ErrMalformed, ck)
			}
			out.Add(ck, v)
		}
	}
	return out, nil
}

func frame(meta any, body []byte) ([]byte, error) {
	mj, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if len(mj) > MaxMeta || len(body) > MaxBody {
		return nil, fmt.Errorf("%w: too large", ErrMalformed)
	}
	out := make([]byte, 4, 4+len(mj)+len(body)+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(out, uint32(len(mj))) //nolint:gosec // bounded above
	out = append(out, mj...)
	return append(out, body...), nil
}

func unframe(pt []byte, meta any) ([]byte, error) {
	if len(pt) < 4 {
		return nil, ErrMalformed
	}
	n := binary.BigEndian.Uint32(pt)
	if n == 0 || n > MaxMeta || int64(n) > int64(len(pt))-4 {
		return nil, ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(pt[4 : 4+n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(meta); err != nil {
		return nil, ErrMalformed
	}
	body := pt[4+n:]
	if len(body) > MaxBody {
		return nil, ErrMalformed
	}
	return append([]byte(nil), body...), nil
}

func validRequestMeta(m RequestMeta) error {
	if len(m.ID) == 0 || len(m.ID) > 64 || m.Method == "" || len(m.Method) > 16 ||
		!strings.HasPrefix(m.Path, "/") || len(m.Path) > 8<<10 || strings.ContainsAny(m.Path, " \r\n\x00#") ||
		strings.ContainsAny(m.Method, " \r\n\x00") {
		return fmt.Errorf("%w: request line", ErrMalformed)
	}
	if _, err := ParsePublicKey(m.ReplyKey); err != nil {
		return fmt.Errorf("%w: reply key", ErrMalformed)
	}
	return nil
}

// SealRequest seals an inner request to the platform's ingest key for the
// route. It assigns the ID and Created time when empty.
func SealRequest(to *PublicKey, r Route, req *Request) ([]byte, error) {
	if req.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		req.ID = hex.EncodeToString(b[:])
	}
	if req.Created.IsZero() {
		req.Created = time.Now().UTC()
	}
	h, err := cleanHeader(req.Header)
	if err != nil {
		return nil, err
	}
	req.Header = h
	if err := validRequestMeta(req.RequestMeta); err != nil {
		return nil, err
	}
	pt, err := frame(req.RequestMeta, req.Body)
	if err != nil {
		return nil, err
	}
	return sealTo(to, KindRequest, r, pt)
}

// OpenRequest opens a request envelope with one of the platform's ingest
// keys (several during a rotation). The returned request is still to be
// authenticated: the platform passes it to its ordinary v2 handling, which
// checks the RFC 9421 signature, nonce, clock and tenant.
func OpenRequest(keys []*PrivateKey, r Route, env []byte) (*Request, error) {
	pt, err := openWith(keys, KindRequest, r, env)
	if err != nil {
		return nil, err
	}
	var req Request
	body, err := unframe(pt, &req.RequestMeta)
	if err != nil {
		return nil, err
	}
	if err := validRequestMeta(req.RequestMeta); err != nil {
		return nil, err
	}
	h, err := cleanHeader(req.Header)
	if err != nil {
		return nil, err
	}
	req.Header, req.Body = h, body
	return &req, nil
}

// ReplyTo is the key the answer to this request is sealed to.
func (r *Request) ReplyTo() (*PublicKey, error) { return ParsePublicKey(r.ReplyKey) }

// ResponseMeta is the inner response without its body.
type ResponseMeta struct {
	// RequestDigest is the hex SHA-256 of the request envelope answered.
	RequestDigest string      `json:"request_digest"`
	Realm         string      `json:"realm"`
	SensorID      string      `json:"sensor_id"`
	Status        int         `json:"status"`
	Header        http.Header `json:"header,omitempty"`
	IssuedAt      time.Time   `json:"issued_at"`
}

// Response is an inner response.
type Response struct {
	Status   int
	Header   http.Header
	Body     []byte
	IssuedAt time.Time
}

// SealResponse signs a response with the platform's response key, binds it
// to the request envelope's digest and the route, and seals it to the
// sensor's encryption key.
func SealResponse(to *PublicKey, signer ed25519.PrivateKey, r Route, requestDigest [32]byte, resp *Response) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("sealed: response signing key required")
	}
	if resp.Status < 100 || resp.Status > 599 {
		return nil, fmt.Errorf("%w: status %d", ErrMalformed, resp.Status)
	}
	h, err := cleanHeader(resp.Header)
	if err != nil {
		return nil, err
	}
	issued := resp.IssuedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	meta := ResponseMeta{RequestDigest: hex.EncodeToString(requestDigest[:]), Realm: r.Realm, SensorID: r.SensorID,
		Status: resp.Status, Header: h, IssuedAt: issued}
	pt, err := frame(meta, resp.Body)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(signer, signedBytes(pt))
	return sealTo(to, KindResponse, r, append(pt, sig...))
}

func signedBytes(pt []byte) []byte {
	out := make([]byte, 0, len(sigLabel)+1+len(pt))
	out = append(out, sigLabel...)
	out = append(out, 0)
	return append(out, pt...)
}

// OpenResponse opens a response with the sensor's encryption key, checks
// the signature against the pinned response keys before parsing anything,
// and checks that it answers requestDigest for this route within
// MaxResponseSkew of now.
func OpenResponse(key *PrivateKey, responseKeys []ed25519.PublicKey, r Route, requestDigest [32]byte, env []byte, now time.Time) (*Response, error) {
	resp, got, err := OpenResponseAny(key, responseKeys, r, env, now)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(got[:], requestDigest[:]) != 1 {
		return nil, ErrBinding
	}
	return resp, nil
}

// OpenResponseAny is OpenResponse for a sensor with several requests
// outstanding: it returns the digest of the request the response answers,
// which the caller matches against its outstanding requests (a response
// for none of them is dropped).
func OpenResponseAny(key *PrivateKey, responseKeys []ed25519.PublicKey, r Route, env []byte, now time.Time) (*Response, [32]byte, error) {
	var none [32]byte
	pt, err := openWith([]*PrivateKey{key}, KindResponse, r, env)
	if err != nil {
		return nil, none, err
	}
	if len(pt) < ed25519.SignatureSize+4 {
		return nil, none, ErrMalformed
	}
	body, sig := pt[:len(pt)-ed25519.SignatureSize], pt[len(pt)-ed25519.SignatureSize:]
	signed := signedBytes(body)
	ok := false
	for _, k := range responseKeys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, signed, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, none, ErrSignature
	}
	var meta ResponseMeta
	b, err := unframe(body, &meta)
	if err != nil {
		return nil, none, err
	}
	digest, err := hex.DecodeString(meta.RequestDigest)
	switch {
	case err != nil || len(digest) != 32, meta.Realm != r.Realm, meta.SensorID != r.SensorID:
		return nil, none, ErrBinding
	case meta.IssuedAt.Before(now.Add(-MaxResponseSkew)) || meta.IssuedAt.After(now.Add(MaxResponseSkew)):
		return nil, none, fmt.Errorf("%w: issued at %s", ErrBinding, meta.IssuedAt.UTC().Format(time.RFC3339))
	case meta.Status < 100 || meta.Status > 599:
		return nil, none, ErrMalformed
	}
	h, err := cleanHeader(meta.Header)
	if err != nil {
		return nil, none, err
	}
	var d [32]byte
	copy(d[:], digest)
	return &Response{Status: meta.Status, Header: h, Body: b, IssuedAt: meta.IssuedAt}, d, nil
}
