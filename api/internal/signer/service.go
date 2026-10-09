package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Paths served on the signer's Unix socket.
const (
	SignPath = "/v1/jobs/sign"
	KeysPath = "/v1/keys"
)

// Config configures a Service.
type Config struct {
	Key ed25519.PrivateKey
	// StateDir holds the per-sensor sequence files (seq/) and the signing
	// log (signing.log).
	StateDir string
	// Per-tenant and per-sensor signing ceilings (token buckets).
	TenantRate  float64
	TenantBurst int
	SensorRate  float64
	SensorBurst int
	Logger      *slog.Logger
	// Now is the clock (tests replace it); nil: time.Now.
	Now func() time.Time
}

// Default ceilings: generous, so they stop a runaway or hostile caller, not
// a busy fleet.
const (
	DefaultTenantRate  = 50
	DefaultTenantBurst = 500
	DefaultSensorRate  = 20
	DefaultSensorBurst = 200
)

// Service signs job statements.
type Service struct {
	key    ed25519.PrivateKey
	keyID  string
	seq    *SeqStore
	log    *SigningLog
	tenant *limiters
	sensor *limiters
	logger *slog.Logger
	now    func() time.Time
}

// New opens the state directory and returns the service.
func New(cfg Config) (*Service, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("signer: an Ed25519 private key is required")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("signer: a state directory is required")
	}
	seq, err := OpenSeqStore(filepath.Join(cfg.StateDir, "seq"))
	if err != nil {
		return nil, err
	}
	lg, err := OpenSigningLog(filepath.Join(cfg.StateDir, "signing.log"))
	if err != nil {
		return nil, err
	}
	pub, _ := cfg.Key.Public().(ed25519.PublicKey)
	s := &Service{
		key: cfg.Key, keyID: jobsign.KeyID(pub), seq: seq, log: lg,
		tenant: newLimiters(orDefault(cfg.TenantRate, DefaultTenantRate), orDefaultInt(cfg.TenantBurst, DefaultTenantBurst)),
		sensor: newLimiters(orDefault(cfg.SensorRate, DefaultSensorRate), orDefaultInt(cfg.SensorBurst, DefaultSensorBurst)),
		logger: cfg.Logger, now: cfg.Now,
	}
	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Close closes the signing log.
func (s *Service) Close() error { return s.log.Close() }

// KeyID is the id of the signing key.
func (s *Service) KeyID() string { return s.keyID }

// Keys is the body of GET /v1/keys.
func (s *Service) Keys() jobsign.KeysResponse {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return jobsign.KeysResponse{PayloadType: jobsign.PayloadType, Keys: []jobsign.PublicKey{jobsign.NewPublicKey(pub)}}
}

// Sign validates a raw statement and returns the DSSE envelope (JSON), or
// the refusal. Every decision is in the signing log before it is returned;
// a decision that cannot be logged is not signed.
func (s *Service) Sign(raw []byte) ([]byte, *refusal) {
	now := s.now()
	st, ref := validate(raw, now)
	if ref == nil {
		switch {
		case !s.tenant.allow(st.TenantID, now):
			ref = refuse(http.StatusTooManyRequests, ReasonTenantRate, "tenant signing ceiling reached")
		case !s.sensor.allow(st.SensorID, now):
			ref = refuse(http.StatusTooManyRequests, ReasonSensorRate, "sensor signing ceiling reached")
		}
	}
	entry := LogEntry{
		Time: now, TenantID: st.TenantID, SensorID: st.SensorID, CommandID: st.CommandID,
		CommandType: st.CommandType, Tool: st.Tool, PayloadSHA256: st.PayloadSHA256, Targets: len(st.Targets),
	}
	if ref != nil {
		s.refused(entry, ref)
		return nil, ref
	}

	seq, err := s.seq.Next(st.SensorID)
	if err != nil {
		s.logger.Error("sequence number not stored; not signing", "error", err)
		ref = refuse(http.StatusInternalServerError, ReasonInternal, "sequence store unavailable")
		s.refused(entry, ref)
		return nil, ref
	}
	nonce := make([]byte, jobsign.NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		ref = refuse(http.StatusInternalServerError, ReasonInternal, "no randomness")
		s.refused(entry, ref)
		return nil, ref
	}
	st.Seq = seq
	st.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	st.Signer = &jobsign.SignerRef{KeyID: s.keyID}
	// The statement is serialized exactly once; these bytes are what is
	// signed and what the sensor verifies and parses.
	payload, err := json.Marshal(st)
	if err != nil {
		ref = refuse(http.StatusInternalServerError, ReasonInternal, "statement does not encode")
		s.refused(entry, ref)
		return nil, ref
	}
	env, err := json.Marshal(jobsign.Sign(s.key, payload))
	if err != nil {
		ref = refuse(http.StatusInternalServerError, ReasonInternal, "envelope does not encode")
		s.refused(entry, ref)
		return nil, ref
	}
	sum := sha256.Sum256(payload)
	entry.Decision, entry.Seq, entry.KeyID = DecisionSigned, seq, s.keyID
	entry.StatementSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	if err := s.log.Append(entry); err != nil {
		s.logger.Error("signing log not written; signature withheld", "error", err)
		return nil, refuse(http.StatusInternalServerError, ReasonInternal, "signing log unavailable")
	}
	return env, nil
}

func (s *Service) refused(e LogEntry, r *refusal) {
	e.Decision, e.Reason = DecisionRefused, r.reason
	if err := s.log.Append(e); err != nil {
		s.logger.Error("signing log not written for a refusal", "error", err, "reason", r.reason)
	}
	s.logger.Warn("job statement refused", "reason", r.reason, "tenant_id", e.TenantID,
		"sensor_id", e.SensorID, "command_id", e.CommandID)
}

// Handler serves the signer's HTTP API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(SignPath, s.handleSign)
	mux.HandleFunc(KeysPath, s.handleKeys)
	return mux
}

func (s *Service) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, jobsign.Refusal{Error: "method_not_allowed"})
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, jobsign.Refusal{Error: "unsupported_media_type"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, jobsign.MaxStatementBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jobsign.Refusal{Error: "refused", Reason: ReasonMalformed})
		return
	}
	env, ref := s.Sign(raw)
	if ref != nil {
		writeJSON(w, ref.status, jobsign.Refusal{Error: "refused", Reason: ref.reason, Detail: ref.detail})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(env)
}

func (s *Service) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, jobsign.Refusal{Error: "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.Keys())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// limiters are token buckets keyed by id. Idle buckets are dropped once the
// map grows past maxLimiters, so a caller cycling ids cannot grow it
// without bound.
type limiters struct {
	mu    sync.Mutex
	rate  rate.Limit
	burst int
	m     map[string]*limiterEntry
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

const (
	maxLimiters   = 100_000
	limiterIdleGC = 10 * time.Minute
)

func newLimiters(r float64, burst int) *limiters {
	return &limiters{rate: rate.Limit(r), burst: burst, m: map[string]*limiterEntry{}}
}

func (l *limiters) allow(id string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[id]
	if !ok {
		if len(l.m) >= maxLimiters {
			for k, v := range l.m {
				if now.Sub(v.seen) > limiterIdleGC {
					delete(l.m, k)
				}
			}
			if len(l.m) >= maxLimiters {
				return false
			}
		}
		e = &limiterEntry{l: rate.NewLimiter(l.rate, l.burst)}
		l.m[id] = e
	}
	e.seen = now
	return e.l.AllowN(now, 1)
}

func orDefault(v, d float64) float64 {
	if v <= 0 {
		return d
	}
	return v
}

func orDefaultInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}
