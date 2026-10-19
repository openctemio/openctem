package sensorrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
)

// The relay connector is the platform side of relay mode: it dials the
// relay with a certificate pinned for its realm, takes the realm's sealed
// requests, opens them with the ingest key, replays each one to the API's
// sensor routes, and seals the API's answer (signed with the response key)
// to the key the request named. It holds the ingest and response keys; the
// API never does, and the relay never sees them.
//
// What reaches the API is the sensor's own signed request: the API checks
// its signature, nonce, clock, rate and tenant exactly as for a direct
// sensor. The connector only lets requests through to the sensor routes
// (relayPathPrefix), never forwards client-address headers, and returns
// no detail on a refusal.

// relayPathPrefix is the only API path prefix a relayed request may reach.
const relayPathPrefix = "/api/v2/sensor/"

// requestHeaders a relayed request may carry to the API (canonical form).
var requestHeaders = map[string]bool{ //nolint:gochecknoglobals // read-only allowlist
	"Accept": true, "Accept-Encoding": true, "Authorization": true, "Content-Digest": true, "Content-Encoding": true,
	"Content-Type": true, "Idempotency-Key": true, "Signature": true, "Signature-Input": true, "User-Agent": true,
	"X-Api-Key": true,
}

// responseHeaders the API's answer may carry back.
var responseHeaders = map[string]bool{ //nolint:gochecknoglobals // read-only allowlist
	"Cache-Control": true, "Content-Digest": true, "Content-Encoding": true, "Content-Type": true, "Retry-After": true,
}

// ConnectorConfig configures a Connector.
type ConnectorConfig struct {
	// RelayURL is the relay's base URL (https).
	RelayURL string
	// RelayPin is the SHA-256 of the relay certificate's
	// SubjectPublicKeyInfo; without it RootCAs verify the relay.
	RelayPin []byte
	RootCAs  *x509.CertPool
	// ClientCert is the connector's certificate (pinned on the relay).
	ClientCert tls.Certificate
	// Realm is the realm the relay serves this connector.
	Realm string
	// IngestKeys open the sensors' requests (two during a rotation).
	IngestKeys []*sealed.PrivateKey
	// ResponseKey signs the answers.
	ResponseKey ed25519.PrivateKey
	// APIURL is the API's base URL on the private network.
	APIURL string
	// APIClient calls the API (default: a client with a 2-minute timeout
	// that ignores proxy settings in the environment and follows no
	// redirect).
	APIClient *http.Client
	// Concurrency is how many requests are replayed at once (default 8).
	Concurrency int
	Logger      *slog.Logger
	Registerer  prometheus.Registerer
	// relayClient overrides the relay HTTP client (tests).
	relayClient *http.Client
}

// Connector is the platform's relay connector.
type Connector struct {
	cfg   ConnectorConfig
	relay *http.Client
	api   *http.Client
	base  string
	apiU  *url.URL
	sem   chan struct{}
	log   *slog.Logger
	met   *connectorMetrics
	wg    sync.WaitGroup
}

type connectorMetrics struct {
	requests *prometheus.CounterVec
}

// NewConnector checks the configuration and builds a connector.
func NewConnector(cfg ConnectorConfig) (*Connector, error) {
	ru, err := url.Parse(cfg.RelayURL)
	if err != nil || ru.Scheme != "https" || ru.Host == "" {
		return nil, errors.New("sensorrelay: connector relay URL must be https")
	}
	au, err := url.Parse(cfg.APIURL)
	if err != nil || (au.Scheme != "http" && au.Scheme != "https") || au.Host == "" {
		return nil, errors.New("sensorrelay: connector API URL must be http(s)")
	}
	switch {
	case !relay.ValidID(cfg.Realm):
		return nil, errors.New("sensorrelay: connector realm required")
	case len(cfg.IngestKeys) == 0:
		return nil, errors.New("sensorrelay: connector ingest key required")
	case len(cfg.ResponseKey) != ed25519.PrivateKeySize:
		return nil, errors.New("sensorrelay: connector response key required")
	case len(cfg.ClientCert.Certificate) == 0:
		return nil, errors.New("sensorrelay: connector client certificate required")
	case cfg.RelayPin != nil && len(cfg.RelayPin) != sha256.Size:
		return nil, errors.New("sensorrelay: relay pin must be a SHA-256")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c := &Connector{cfg: cfg, base: strings.TrimRight(cfg.RelayURL, "/"), apiU: au, sem: make(chan struct{}, cfg.Concurrency), log: cfg.Logger}
	c.relay = cfg.relayClient
	if c.relay == nil {
		c.relay = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: connectorTLS(cfg, ru.Hostname()), ForceAttemptHTTP2: true}}
	}
	c.api = cfg.APIClient
	if c.api == nil {
		c.api = newAPIClient()
	}
	c.met = &connectorMetrics{requests: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_relay_connector_requests_total",
		Help: "Relayed sensor requests handled by the connector, by outcome.",
	}, []string{"outcome"})}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(c.met.requests)
	}
	return c, nil
}

// newAPIClient is the default client for the API on the private network.
// It never uses a proxy from the environment (HTTPS_PROXY, HTTP_PROXY): the
// requests it carries are the sensors' opened requests, and an egress proxy
// configured for the host must not see them. It never follows redirects.
func newAPIClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's own type
	tr.Proxy = nil
	return &http.Client{Timeout: 2 * time.Minute, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func connectorTLS(cfg ConnectorConfig, serverName string) *tls.Config {
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cfg.ClientCert}, RootCAs: cfg.RootCAs, ServerName: serverName}
	if cfg.RelayPin != nil {
		pin := append([]byte(nil), cfg.RelayPin...)
		t.InsecureSkipVerify = true //nolint:gosec // VerifyConnection checks the pinned key instead of the chain
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("sensorrelay: relay sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("sensorrelay: relay certificate does not match the pin")
			}
			return nil
		}
	}
	return t
}

// Run takes the realm's requests from the relay until ctx ends. Failures
// back off with full jitter up to 60 s.
func (c *Connector) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		items, err := c.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			c.log.Warn("relay connector: poll failed", "error", err.Error())
			wait := time.Duration(mrand.Int64N(int64(backoff))) //nolint:gosec // jitter
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}
		backoff = time.Second
		for _, it := range items {
			select {
			case c.sem <- struct{}{}:
			case <-ctx.Done():
				c.wg.Wait()
				return
			}
			c.wg.Add(1)
			go func(it relay.Item) {
				defer func() { <-c.sem; c.wg.Done() }()
				c.handle(ctx, it)
			}(it)
		}
	}
	c.wg.Wait()
}

func (c *Connector) poll(ctx context.Context) ([]relay.Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+relay.PathConnectorUp+"?wait=25", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.relay.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		return relay.ReadBatch(io.LimitReader(resp.Body, 64<<20+1<<16), 64, 64<<20)
	default:
		return nil, fmt.Errorf("relay answered %d", resp.StatusCode)
	}
}

// handle replays one relayed request and posts the sealed answer.
func (c *Connector) handle(ctx context.Context, it relay.Item) {
	route := sealed.Route{Realm: c.cfg.Realm, SensorID: it.Sensor}
	req, err := sealed.OpenRequest(c.cfg.IngestKeys, route, it.Envelope)
	if err != nil {
		// Nothing can be answered: there is no key to answer to.
		c.met.requests.WithLabelValues("refused").Inc()
		c.log.Debug("relay connector: envelope refused", "sensor", it.Sensor, "error", err.Error())
		return
	}
	replyTo, err := req.ReplyTo()
	if err != nil {
		c.met.requests.WithLabelValues("refused").Inc()
		return
	}
	answer := c.replay(ctx, req)
	env, err := sealed.SealResponse(replyTo, c.cfg.ResponseKey, route, sealed.Digest(it.Envelope), answer)
	if err != nil {
		c.met.requests.WithLabelValues("seal_failed").Inc()
		c.log.Warn("relay connector: cannot seal the answer", "sensor", it.Sensor, "error", err.Error())
		return
	}
	if err := c.postDown(ctx, it.Sensor, env); err != nil {
		c.met.requests.WithLabelValues("undelivered").Inc()
		c.log.Warn("relay connector: cannot post the answer", "sensor", it.Sensor, "error", err.Error())
		return
	}
	c.met.requests.WithLabelValues("answered_" + strconv.Itoa(answer.Status/100) + "xx").Inc()
}

// allowedPath reports whether a relayed request path (with its query) is
// a clean path under the sensor routes.
func allowedPath(p string) bool {
	u, err := url.ParseRequestURI(p)
	if err != nil || u.Host != "" || u.Scheme != "" || u.Opaque != "" || u.RawPath != "" && u.RawPath != u.EscapedPath() {
		return false
	}
	if strings.Contains(u.Path, "//") || strings.Contains(p, "%2e") || strings.Contains(p, "%2E") || strings.Contains(p, "%2f") || strings.Contains(p, "%2F") {
		return false
	}
	clean := path.Clean(u.Path)
	if strings.HasSuffix(u.Path, "/") && clean != "/" {
		clean += "/"
	}
	return clean == u.Path && strings.HasPrefix(u.Path, relayPathPrefix)
}

func plain(status int, msg string) *sealed.Response {
	return &sealed.Response{Status: status, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, Body: []byte(msg)}
}

// replay sends the inner request to the API and returns its answer.
func (c *Connector) replay(ctx context.Context, in *sealed.Request) *sealed.Response {
	if !allowedPath(in.Path) {
		c.met.requests.WithLabelValues("path_refused").Inc()
		return plain(http.StatusForbidden, "forbidden")
	}
	target := *c.apiU
	target.Path = strings.TrimRight(c.apiU.Path, "/")
	u, _ := url.ParseRequestURI(in.Path)
	target.Path += u.Path
	target.RawQuery = u.RawQuery
	req, err := http.NewRequestWithContext(ctx, in.Method, target.String(), bytes.NewReader(in.Body))
	if err != nil {
		return plain(http.StatusBadRequest, "bad request")
	}
	for k, vs := range in.Header {
		if requestHeaders[http.CanonicalHeaderKey(k)] {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	req.ContentLength = int64(len(in.Body))
	resp, err := c.api.Do(req)
	if err != nil {
		c.log.Warn("relay connector: API unreachable", "error", err.Error())
		return plain(http.StatusBadGateway, "platform unavailable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, sealed.MaxBody+1))
	if err != nil || len(body) > sealed.MaxBody {
		return plain(http.StatusBadGateway, "answer too large")
	}
	out := &sealed.Response{Status: resp.StatusCode, Header: http.Header{}, Body: body}
	for k, vs := range resp.Header {
		if responseHeaders[http.CanonicalHeaderKey(k)] {
			for _, v := range vs {
				out.Header.Add(k, v)
			}
		}
	}
	return out
}

func (c *Connector) postDown(ctx context.Context, sensor string, env []byte) error {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+relay.PathConnectorDown+url.PathEscape(sensor), bytes.NewReader(env))
		if err != nil {
			return err
		}
		resp, err := c.relay.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusAccepted:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests && attempt < 3:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		default:
			return fmt.Errorf("relay answered %d", resp.StatusCode)
		}
	}
}
