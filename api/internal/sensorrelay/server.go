// Package sensorrelay is the sensor relay: a small stateless broker that
// sensors and the platform's relay connector both dial out to, so a sensor
// on the internet can work for a platform that is only reachable inside a
// private network. Design: docs/rfcs/RFC-116-sensor-relay.md; operation:
// docs/architecture/sensor-relay.md.
//
// The relay moves sealed envelopes and nothing else. It cannot read them
// (sealed to the platform's ingest key or to the sensor's key), cannot
// change them, and cannot answer in the platform's name. What it decides is
// only who may put and take envelopes:
//
//   - a sensor authenticates with a TLS client certificate holding its
//     identity key and a ticket the platform signed for that key, this
//     relay and one realm; its mailbox is (realm, sensor) from the ticket,
//     never from the request;
//   - a relay connector authenticates with a TLS client certificate whose
//     public key is pinned for one realm, and sees only that realm.
//
// Everything is held in memory under per-sensor and total quotas and
// dropped after a TTL; logs carry ids, sizes and outcomes, never envelope
// bytes or request details.
package sensorrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
)

// Realm is one platform installation (or cell) the relay serves.
type Realm struct {
	Name string
	// TicketKeys verify the tickets the realm's platform issues (two
	// during a rotation).
	TicketKeys []ed25519.PublicKey
	// ConnectorPins are the SHA-256 of the SubjectPublicKeyInfo of the
	// realm's relay connector certificates.
	ConnectorPins [][32]byte
}

// Limits bound what the relay holds and serves.
type Limits struct {
	MailboxItems      int
	MailboxBytes      int64
	TotalBytes        int64
	TTL               time.Duration
	SensorRate        float64
	SensorBurst       int
	MaxWait           time.Duration
	MaxPollsPerSensor int
	BatchItems        int
	BatchBytes        int64
}

// DefaultLimits are the relay's defaults.
var DefaultLimits = Limits{ //nolint:gochecknoglobals // read-only defaults
	MailboxItems:      64,
	MailboxBytes:      64 << 20,
	TotalBytes:        2 << 30,
	TTL:               10 * time.Minute,
	SensorRate:        10,
	SensorBurst:       20,
	MaxWait:           25 * time.Second,
	MaxPollsPerSensor: 2,
	BatchItems:        32,
	BatchBytes:        32 << 20,
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.MailboxItems > 0 {
		d.MailboxItems = l.MailboxItems
	}
	if l.MailboxBytes > 0 {
		d.MailboxBytes = l.MailboxBytes
	}
	if l.TotalBytes > 0 {
		d.TotalBytes = l.TotalBytes
	}
	if l.TTL > 0 {
		d.TTL = l.TTL
	}
	if l.SensorRate > 0 {
		d.SensorRate = l.SensorRate
	}
	if l.SensorBurst > 0 {
		d.SensorBurst = l.SensorBurst
	}
	if l.MaxWait > 0 {
		d.MaxWait = l.MaxWait
	}
	if l.MaxPollsPerSensor > 0 {
		d.MaxPollsPerSensor = l.MaxPollsPerSensor
	}
	if l.BatchItems > 0 {
		d.BatchItems = l.BatchItems
	}
	if l.BatchBytes > 0 {
		d.BatchBytes = l.BatchBytes
	}
	if d.BatchBytes < relay.MaxEnvelope {
		d.BatchBytes = relay.MaxEnvelope
	}
	return d
}

// Config configures a Server.
type Config struct {
	// RelayID is this relay's id: tickets name it.
	RelayID string
	Realms  []Realm
	Limits  Limits
	Logger  *slog.Logger
	// Registerer receives the relay's metrics (nil: none).
	Registerer prometheus.Registerer

	now func() time.Time
}

// Server is the relay.
type Server struct {
	cfg    Config
	lim    Limits
	log    *slog.Logger
	realms map[string]*Realm
	pins   map[[32]byte]string // connector pin -> realm
	boxes  *mailboxes
	met    *metrics

	mu       sync.Mutex
	limiters map[sensorKey]*limiterEntry
	polls    map[sensorKey]int
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// New checks the configuration and builds a relay.
func New(cfg Config) (*Server, error) {
	if !relay.ValidID(cfg.RelayID) {
		return nil, fmt.Errorf("sensorrelay: invalid relay id %q", cfg.RelayID)
	}
	if len(cfg.Realms) == 0 {
		return nil, errors.New("sensorrelay: no realm configured")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	s := &Server{cfg: cfg, lim: cfg.Limits.withDefaults(), log: cfg.Logger, realms: map[string]*Realm{},
		pins: map[[32]byte]string{}, limiters: map[sensorKey]*limiterEntry{}, polls: map[sensorKey]int{}}
	for i := range cfg.Realms {
		r := &cfg.Realms[i]
		if !relay.ValidID(r.Name) {
			return nil, fmt.Errorf("sensorrelay: invalid realm name %q", r.Name)
		}
		if _, dup := s.realms[r.Name]; dup {
			return nil, fmt.Errorf("sensorrelay: realm %s configured twice", r.Name)
		}
		if len(r.TicketKeys) == 0 || len(r.ConnectorPins) == 0 {
			return nil, fmt.Errorf("sensorrelay: realm %s needs a ticket key and a connector pin", r.Name)
		}
		for _, k := range r.TicketKeys {
			if len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("sensorrelay: realm %s: invalid ticket key", r.Name)
			}
		}
		for _, p := range r.ConnectorPins {
			if other, dup := s.pins[p]; dup {
				return nil, fmt.Errorf("sensorrelay: one connector pin in realms %s and %s", other, r.Name)
			}
			s.pins[p] = r.Name
		}
		s.realms[r.Name] = r
	}
	s.boxes = newMailboxes(s.lim, cfg.now)
	s.met = newMetrics(cfg.Registerer)
	return s, nil
}

// TLSConfig is the listener's TLS configuration: TLS 1.3 only, and a client
// certificate is required on every connection (who it belongs to is
// decided per request: a sensor by its ticket, a connector by its pin).
func (s *Server) TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// Run expires old envelopes and idle limiters until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *Server) sweep() {
	if n := s.boxes.expire(); n > 0 {
		s.met.envelopes.WithLabelValues("any", "expired").Add(float64(n))
		s.log.Info("relay: envelopes expired unclaimed", "count", n)
	}
	s.met.held.Set(float64(s.boxes.held()))
	cutoff := s.cfg.now().Add(-10 * time.Minute)
	s.mu.Lock()
	for k, e := range s.limiters {
		if e.seen.Before(cutoff) {
			delete(s.limiters, k)
		}
	}
	s.mu.Unlock()
}

// Handler is the relay's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+relay.PathSensorUp, s.sensorUp)
	mux.HandleFunc("GET "+relay.PathSensorDown, s.sensorDown)
	mux.HandleFunc("GET "+relay.PathConnectorUp, s.connectorUp)
	mux.HandleFunc("POST "+relay.PathConnectorDown+"{sensor}", s.connectorDown)
	return mux
}

// sensorPrincipal authenticates a sensor request: the ticket verifies
// under its realm's keys, names this relay, is valid now, and its key is
// the TLS client certificate's key.
func (s *Server) sensorPrincipal(r *http.Request) (relay.Ticket, bool) {
	var none relay.Ticket
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return none, false
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return none, false
	}
	token := r.Header.Get(relay.TicketHeader)
	realmName, ok := relay.PeekRealm(token)
	if !ok {
		return none, false
	}
	realm := s.realms[realmName]
	if realm == nil {
		return none, false
	}
	t, err := relay.VerifyTicket(token, realm.TicketKeys, s.cfg.RelayID, s.cfg.now())
	if err != nil || !t.KeyMatches(pub) {
		s.log.Debug("relay: sensor ticket refused", "realm", realmName)
		return none, false
	}
	return t, true
}

// connectorRealm authenticates a connector by its pinned public key.
func (s *Server) connectorRealm(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	pin := sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	realm, ok := s.pins[pin]
	return realm, ok
}

func (s *Server) refuse(w http.ResponseWriter, side string) {
	s.met.authFailures.WithLabelValues(side).Inc()
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
	http.Error(w, "too many requests", http.StatusTooManyRequests)
}

func (s *Server) allow(k sensorKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.limiters[k]
	if e == nil {
		e = &limiterEntry{l: rate.NewLimiter(rate.Limit(s.lim.SensorRate), s.lim.SensorBurst)}
		s.limiters[k] = e
	}
	e.seen = s.cfg.now()
	return e.l.Allow()
}

// readEnvelope reads one envelope body.
func readEnvelope(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, relay.MaxEnvelope))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "envelope too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return nil, false
	}
	if len(body) == 0 {
		http.Error(w, "empty envelope", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (s *Server) sensorUp(w http.ResponseWriter, r *http.Request) {
	t, ok := s.sensorPrincipal(r)
	if !ok {
		s.refuse(w, "sensor")
		return
	}
	k := sensorKey{t.Realm, t.Sensor}
	if !s.allow(k) {
		s.met.envelopes.WithLabelValues("up", "rate_limited").Inc()
		tooMany(w, time.Second)
		return
	}
	env, ok := readEnvelope(w, r)
	if !ok {
		s.met.envelopes.WithLabelValues("up", "refused").Inc()
		return
	}
	if err := s.boxes.putUp(t.Realm, t.Sensor, env); err != nil {
		s.met.envelopes.WithLabelValues("up", "quota").Inc()
		tooMany(w, 5*time.Second)
		return
	}
	s.met.envelopes.WithLabelValues("up", "queued").Inc()
	w.WriteHeader(http.StatusAccepted)
}

// waitOf reads ?wait= (seconds), bounded by MaxWait.
func (s *Server) waitOf(r *http.Request) time.Duration {
	n, err := strconv.Atoi(r.URL.Query().Get("wait"))
	if err != nil || n < 0 {
		return 0
	}
	d := time.Duration(n) * time.Second
	if d > s.lim.MaxWait {
		d = s.lim.MaxWait
	}
	return d
}

func (s *Server) sensorDown(w http.ResponseWriter, r *http.Request) {
	t, ok := s.sensorPrincipal(r)
	if !ok {
		s.refuse(w, "sensor")
		return
	}
	k := sensorKey{t.Realm, t.Sensor}
	s.mu.Lock()
	if s.polls[k] >= s.lim.MaxPollsPerSensor {
		s.mu.Unlock()
		tooMany(w, time.Second)
		return
	}
	s.polls[k]++
	s.mu.Unlock()
	s.met.polls.Inc()
	defer func() {
		s.met.polls.Dec()
		s.mu.Lock()
		if s.polls[k]--; s.polls[k] <= 0 {
			delete(s.polls, k)
		}
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(r.Context(), s.waitOf(r))
	defer cancel()
	items := s.boxes.takeDown(ctx, t.Realm, t.Sensor, s.lim.BatchItems, s.lim.BatchBytes)
	s.writeBatch(w, items, "down")
}

func (s *Server) connectorUp(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.connectorRealm(r)
	if !ok {
		s.refuse(w, "connector")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.waitOf(r))
	defer cancel()
	items := s.boxes.takeUp(ctx, realm, s.lim.BatchItems, s.lim.BatchBytes)
	s.writeBatch(w, items, "up")
}

func (s *Server) connectorDown(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.connectorRealm(r)
	if !ok {
		s.refuse(w, "connector")
		return
	}
	sensor := r.PathValue("sensor")
	if !relay.ValidID(sensor) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	env, ok := readEnvelope(w, r)
	if !ok {
		s.met.envelopes.WithLabelValues("down", "refused").Inc()
		return
	}
	if err := s.boxes.putDown(realm, sensor, env); err != nil {
		s.met.envelopes.WithLabelValues("down", "quota").Inc()
		tooMany(w, 5*time.Second)
		return
	}
	s.met.envelopes.WithLabelValues("down", "queued").Inc()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) writeBatch(w http.ResponseWriter, items []relay.Item, dir string) {
	if len(items) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var buf bytes.Buffer
	if err := relay.WriteBatch(&buf, items); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", relay.BatchContentType)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
	s.met.envelopes.WithLabelValues(dir, "delivered").Add(float64(len(items)))
}

// ParsePin reads a connector pin: the hex SHA-256 of a certificate's
// SubjectPublicKeyInfo ("sha256:" prefix allowed).
func ParsePin(s string) ([32]byte, error) {
	var p [32]byte
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "sha256:"))))
	if err != nil || len(b) != len(p) {
		return p, errors.New("sensorrelay: a pin is 64 hex characters (sha256 of the SubjectPublicKeyInfo)")
	}
	copy(p[:], b)
	return p, nil
}

// PinOf is the pin of a certificate (DER).
func PinOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}
