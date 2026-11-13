// Package relay is the wire contract of the sensor relay: the tickets the
// platform issues so a sensor may use a relay, and the batch framing the
// relay's mailboxes use. Design: docs/rfcs/RFC-116-sensor-relay.md.
//
// The relay never sees plaintext: what it carries are sealed envelopes
// (the sensor's signed request sealed to the platform's ingest key, the
// platform's signed response sealed to the sensor's key). This package
// only defines who may put and take envelopes, and how several are framed
// in one HTTP body.
package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Paths and headers.
const (
	// TicketHeader carries the sensor's ticket on every sensor request.
	TicketHeader = "Openctem-Relay-Ticket"
	// BatchContentType is the media type of a framed batch.
	BatchContentType = "application/vnd.openctem.relay-batch"

	PathSensorUp      = "/v1/sensor/up"
	PathSensorDown    = "/v1/sensor/down"
	PathConnectorUp   = "/v1/connector/up"
	PathConnectorDown = "/v1/connector/down/" // + sensor id
)

// HeaderRelaySensor is set by the relay connector on every request it
// replays to the API, to the sensor id of the route the envelope arrived
// on. The API refuses a signed request whose verified signing sensor is
// another one.
const HeaderRelaySensor = "X-Relay-Sensor"

// Limits shared by both ends.
const (
	// MaxEnvelope bounds one envelope (the sealed v2 request body cap plus
	// the envelope overhead).
	MaxEnvelope = 16<<20 + 64<<10
	// MaxTicketTTL bounds a ticket's validity.
	MaxTicketTTL = 24 * time.Hour
	// MaxTicketBytes bounds the ticket header.
	MaxTicketBytes = 4 << 10
	// TicketSkew is the clock skew tolerated on iat and exp.
	TicketSkew = 2 * time.Minute

	ticketPrefix = "v1."
	ticketLabel  = "openctem-relay-ticket/v1"
)

// idRE is the form of realm, relay, tenant and sensor ids.
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID reports whether s is a well-formed id.
func ValidID(s string) bool { return idRE.MatchString(s) && !strings.Contains(s, "..") }

// Errors.
var (
	ErrTicket       = errors.New("relay: ticket refused")
	ErrTicketExpiry = errors.New("relay: ticket expired or not yet valid")
	ErrFrame        = errors.New("relay: malformed batch")
)

// Ticket lets one sensor use one relay for one realm until Exp. The
// platform signs it (TicketKey); the relay checks the signature with the
// realm's pinned ticket keys and that the TLS client key is Key.
type Ticket struct {
	V      int    `json:"v"`
	Realm  string `json:"realm"`
	Tenant string `json:"tenant"`
	Sensor string `json:"sensor"`
	// Key is the sensor's Ed25519 identity public key: the relay requires
	// the TLS client certificate to carry it.
	Key   []byte `json:"key"`
	Relay string `json:"relay"`
	IAT   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

func (t Ticket) check() error {
	switch {
	case t.V != 1:
		return fmt.Errorf("%w: version %d", ErrTicket, t.V)
	case !ValidID(t.Realm), !ValidID(t.Tenant), !ValidID(t.Sensor), !ValidID(t.Relay):
		return fmt.Errorf("%w: id", ErrTicket)
	case len(t.Key) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: key", ErrTicket)
	case t.Exp <= t.IAT || time.Duration(t.Exp-t.IAT)*time.Second > MaxTicketTTL:
		return fmt.Errorf("%w: validity", ErrTicket)
	}
	return nil
}

func signed(payload []byte) []byte {
	out := append([]byte(ticketLabel), 0)
	return append(out, payload...)
}

// SignTicket encodes and signs a ticket.
func SignTicket(key ed25519.PrivateKey, t Ticket) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("relay: ticket key required")
	}
	if err := t.check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, signed(payload))
	enc := base64.RawURLEncoding
	return ticketPrefix + enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// VerifyTicket checks a ticket's signature against keys (any of them), its
// form and its validity at now, and that it is for relayID. It does not
// check the TLS key: the caller compares Ticket.Key with the client
// certificate (KeyMatches).
func VerifyTicket(token string, keys []ed25519.PublicKey, relayID string, now time.Time) (Ticket, error) {
	var t Ticket
	if len(token) > MaxTicketBytes {
		return t, fmt.Errorf("%w: too long", ErrTicket)
	}
	rest, ok := strings.CutPrefix(token, ticketPrefix)
	if !ok {
		return t, fmt.Errorf("%w: format", ErrTicket)
	}
	p64, s64, ok := strings.Cut(rest, ".")
	if !ok {
		return t, fmt.Errorf("%w: format", ErrTicket)
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p64)
	sig, err2 := enc.DecodeString(s64)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return t, fmt.Errorf("%w: encoding", ErrTicket)
	}
	verified := false
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, signed(payload), sig) {
			verified = true
			break
		}
	}
	if !verified {
		return t, fmt.Errorf("%w: signature", ErrTicket)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Ticket{}, fmt.Errorf("%w: payload", ErrTicket)
	}
	if err := t.check(); err != nil {
		return Ticket{}, err
	}
	if t.Relay != relayID {
		return Ticket{}, fmt.Errorf("%w: issued for another relay", ErrTicket)
	}
	skew := int64(TicketSkew / time.Second)
	if now.Unix() >= t.Exp+skew || now.Unix() < t.IAT-skew {
		return Ticket{}, ErrTicketExpiry
	}
	return t, nil
}

// PeekRealm returns the realm a ticket claims, without verifying it: the
// relay uses it only to pick the realm's keys for VerifyTicket.
func PeekRealm(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, ticketPrefix)
	if !ok || len(token) > MaxTicketBytes {
		return "", false
	}
	p64, _, ok := strings.Cut(rest, ".")
	if !ok {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(p64)
	if err != nil {
		return "", false
	}
	var t struct {
		Realm string `json:"realm"`
	}
	if json.Unmarshal(payload, &t) != nil || !ValidID(t.Realm) {
		return "", false
	}
	return t.Realm, true
}

// KeyMatches reports whether the ticket's key is pub (constant time).
func (t Ticket) KeyMatches(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(t.Key, pub) == 1
}

// Item is one envelope in a batch. Sensor is empty in batches sent to a
// sensor (its own mailbox) and set in batches sent to a connector.
type Item struct {
	Sensor   string
	Envelope []byte
}

// WriteBatch frames items: for each, u16 sensor length || sensor || u32
// envelope length || envelope.
func WriteBatch(w io.Writer, items []Item) error {
	var hdr [6]byte
	for _, it := range items {
		if len(it.Sensor) > 128 || len(it.Envelope) == 0 || len(it.Envelope) > MaxEnvelope {
			return ErrFrame
		}
		binary.BigEndian.PutUint16(hdr[:2], uint16(len(it.Sensor)))   //nolint:gosec // bounded above
		binary.BigEndian.PutUint32(hdr[2:], uint32(len(it.Envelope))) //nolint:gosec // bounded above
		if _, err := w.Write(hdr[:2]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, it.Sensor); err != nil {
			return err
		}
		if _, err := w.Write(hdr[2:]); err != nil {
			return err
		}
		if _, err := w.Write(it.Envelope); err != nil {
			return err
		}
	}
	return nil
}

// ReadBatch reads a framed batch of at most maxItems items and maxBytes
// envelope bytes in total.
func ReadBatch(r io.Reader, maxItems int, maxBytes int64) ([]Item, error) {
	var items []Item
	var total int64
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:2]); err != nil {
			if errors.Is(err, io.EOF) {
				return items, nil
			}
			return nil, ErrFrame
		}
		if len(items) >= maxItems {
			return nil, ErrFrame
		}
		sl := int(binary.BigEndian.Uint16(hdr[:2]))
		if sl > 128 {
			return nil, ErrFrame
		}
		sensor := make([]byte, sl)
		if _, err := io.ReadFull(r, sensor); err != nil {
			return nil, ErrFrame
		}
		if sl > 0 && !ValidID(string(sensor)) {
			return nil, ErrFrame
		}
		if _, err := io.ReadFull(r, hdr[:4]); err != nil {
			return nil, ErrFrame
		}
		el := int64(binary.BigEndian.Uint32(hdr[:4]))
		if el == 0 || el > MaxEnvelope || total+el > maxBytes {
			return nil, ErrFrame
		}
		total += el
		env := make([]byte, el)
		if _, err := io.ReadFull(r, env); err != nil {
			return nil, ErrFrame
		}
		items = append(items, Item{Sensor: string(sensor), Envelope: env})
	}
}
