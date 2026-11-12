// Command openctem-sensor-relay is the sensor relay: sensors and the
// platform's relay connector both dial out to it, so a sensor outside a
// network can work for a platform inside it. It moves sealed envelopes it
// cannot read. Design: docs/rfcs/RFC-116-sensor-relay.md; operation:
// docs/architecture/sensor-relay.md.
//
//	openctem-sensor-relay [serve]           serve (RELAY_CONFIG, RELAY_TLS_CERT, RELAY_TLS_KEY)
//	openctem-sensor-relay check             load and check the configuration, then exit
//	openctem-sensor-relay pin -cert FILE    print the pin of a certificate (PEM)
//
// The platform side, next to the API on the private network:
//
//	openctem-sensor-relay connector                 run the relay connector (CONNECTOR_* below)
//	openctem-sensor-relay ingest-keygen -out FILE   create the ingest key, print its public half
//	openctem-sensor-relay response-keygen -out FILE create the response key, print its public half
//	openctem-sensor-relay ticket-keygen -out FILE   create the ticket key, print its public half (relay configuration)
//	openctem-sensor-relay ticket -key FILE -realm R -tenant T -sensor S -sensor-key K -relay ID [-ttl D]
//	                                                mint one ticket (until the platform issues them)
//
// Connector environment: CONNECTOR_RELAY_URL, CONNECTOR_RELAY_PIN (hex
// SHA-256 of the relay's public key), CONNECTOR_TLS_CERT, CONNECTOR_TLS_KEY
// (its client certificate, pinned on the relay), CONNECTOR_REALM,
// CONNECTOR_INGEST_KEYS (comma-separated key files), CONNECTOR_RESPONSE_KEY,
// CONNECTOR_API_URL (the API on the private network), CONNECTOR_HEALTH_LISTEN
// (default 127.0.0.1:9091).
//
// Environment: RELAY_CONFIG (YAML, default /etc/openctem-relay/relay.yaml),
// RELAY_LISTEN (default :8443), RELAY_TLS_CERT, RELAY_TLS_KEY,
// RELAY_HEALTH_LISTEN (health and metrics, default 127.0.0.1:9090; never
// expose it).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/sensorrelay"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openctem-sensor-relay:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve()
	case "check":
		cfg, err := loadConfig(envOr("RELAY_CONFIG", "/etc/openctem-relay/relay.yaml"))
		if err != nil {
			return err
		}
		if _, err := sensorrelay.New(cfg); err != nil {
			return err
		}
		fmt.Printf("configuration ok: relay %s, %d realm(s)\n", cfg.RelayID, len(cfg.Realms))
		return nil
	case "connector":
		return runConnector()
	case "ingest-keygen":
		return keygen("ingest", args)
	case "response-keygen":
		return keygen("response", args)
	case "ticket-keygen":
		return keygen("ticket", args)
	case "ticket":
		return ticketSign(args)
	case "pin":
		fs := flag.NewFlagSet("pin", flag.ContinueOnError)
		certFile := fs.String("cert", "", "connector certificate (PEM)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return printPin(*certFile)
	default:
		return fmt.Errorf("unknown command %q (serve, check, pin, connector, ingest-keygen, response-keygen, ticket-keygen, ticket)", cmd)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// fileConfig is the YAML configuration.
type fileConfig struct {
	RelayID string `yaml:"relay_id"`
	Realms  []struct {
		Name          string   `yaml:"name"`
		TicketKeys    []string `yaml:"ticket_keys"`
		ConnectorPins []string `yaml:"connector_pins"`
	} `yaml:"realms"`
	Limits struct {
		MailboxItems      int           `yaml:"mailbox_items"`
		MailboxBytes      int64         `yaml:"mailbox_bytes"`
		TotalBytes        int64         `yaml:"total_bytes"`
		RealmBytes        int64         `yaml:"realm_bytes"`
		TTL               time.Duration `yaml:"ttl"`
		SensorRate        float64       `yaml:"sensor_rate"`
		SensorBurst       int           `yaml:"sensor_burst"`
		MaxWait           time.Duration `yaml:"max_wait"`
		MaxPollsPerSensor int           `yaml:"max_polls_per_sensor"`
	} `yaml:"limits"`
}

func loadConfig(path string) (sensorrelay.Config, error) {
	var out sensorrelay.Config
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's configuration file
	if err != nil {
		return out, fmt.Errorf("read %s: %w", path, err)
	}
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return out, fmt.Errorf("parse %s: %w", path, err)
	}
	out.RelayID = fc.RelayID
	for _, r := range fc.Realms {
		realm := sensorrelay.Realm{Name: r.Name}
		for _, k := range r.TicketKeys {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(b) != ed25519.PublicKeySize {
				return out, fmt.Errorf("realm %s: a ticket key is a base64 Ed25519 public key", r.Name)
			}
			realm.TicketKeys = append(realm.TicketKeys, ed25519.PublicKey(b))
		}
		for _, p := range r.ConnectorPins {
			pin, err := sensorrelay.ParsePin(p)
			if err != nil {
				return out, fmt.Errorf("realm %s: %w", r.Name, err)
			}
			realm.ConnectorPins = append(realm.ConnectorPins, pin)
		}
		out.Realms = append(out.Realms, realm)
	}
	l := fc.Limits
	out.Limits = sensorrelay.Limits{MailboxItems: l.MailboxItems, MailboxBytes: l.MailboxBytes, TotalBytes: l.TotalBytes, RealmBytes: l.RealmBytes,
		TTL: l.TTL, SensorRate: l.SensorRate, SensorBurst: l.SensorBurst, MaxWait: l.MaxWait, MaxPollsPerSensor: l.MaxPollsPerSensor}
	return out, nil
}

func printPin(certFile string) error {
	if certFile == "" {
		return errors.New("-cert is required")
	}
	raw, err := os.ReadFile(certFile) //nolint:gosec // the operator's certificate file
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return errors.New("not a PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	fmt.Println(sensorrelay.PinOf(c.RawSubjectPublicKeyInfo))
	return nil
}

func serve() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := loadConfig(envOr("RELAY_CONFIG", "/etc/openctem-relay/relay.yaml"))
	if err != nil {
		return err
	}
	reg := prometheus.NewRegistry()
	cfg.Logger, cfg.Registerer = log, reg
	srv, err := sensorrelay.New(cfg)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("RELAY_TLS_CERT"), os.Getenv("RELAY_TLS_KEY"))
	if err != nil {
		return fmt.Errorf("TLS certificate (RELAY_TLS_CERT, RELAY_TLS_KEY): %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Run(ctx)

	apiSrv := &http.Server{
		Addr:              envOr("RELAY_LISTEN", ":8443"),
		Handler:           srv.Handler(),
		TLSConfig:         srv.TLSConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	healthMux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	health := &http.Server{Addr: envOr("RELAY_HEALTH_LISTEN", "127.0.0.1:9090"), Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- apiSrv.ListenAndServeTLS("", "") }()
	go func() { errc <- health.ListenAndServe() }()
	log.Info("relay started", "relay_id", cfg.RelayID, "realms", len(cfg.Realms), "listen", apiSrv.Addr, "health", health.Addr)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = health.Shutdown(shutdown)
	return apiSrv.Shutdown(shutdown)
}

func runConnector() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cert, err := tls.LoadX509KeyPair(os.Getenv("CONNECTOR_TLS_CERT"), os.Getenv("CONNECTOR_TLS_KEY"))
	if err != nil {
		return fmt.Errorf("client certificate (CONNECTOR_TLS_CERT, CONNECTOR_TLS_KEY): %w", err)
	}
	files := strings.Split(os.Getenv("CONNECTOR_INGEST_KEYS"), ",")
	ingest := make([]*sealed.PrivateKey, 0, len(files))
	for _, f := range files {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		k, err := loadIngestKey(f)
		if err != nil {
			return fmt.Errorf("CONNECTOR_INGEST_KEYS: %w", err)
		}
		ingest = append(ingest, k)
	}
	resp, err := loadEd25519Key(os.Getenv("CONNECTOR_RESPONSE_KEY"))
	if err != nil {
		return fmt.Errorf("CONNECTOR_RESPONSE_KEY: %w", err)
	}
	var pin []byte
	if v := os.Getenv("CONNECTOR_RELAY_PIN"); v != "" {
		p, err := sensorrelay.ParsePin(v)
		if err != nil {
			return fmt.Errorf("CONNECTOR_RELAY_PIN: %w", err)
		}
		pin = p[:]
	}
	reg := prometheus.NewRegistry()
	c, err := sensorrelay.NewConnector(sensorrelay.ConnectorConfig{
		RelayURL: os.Getenv("CONNECTOR_RELAY_URL"), RelayPin: pin, ClientCert: cert, Realm: os.Getenv("CONNECTOR_REALM"),
		IngestKeys: ingest, ResponseKey: resp, APIURL: os.Getenv("CONNECTOR_API_URL"), Logger: log, Registerer: reg,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	healthMux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	health := &http.Server{Addr: envOr("CONNECTOR_HEALTH_LISTEN", "127.0.0.1:9091"), Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = health.ListenAndServe() }()
	log.Info("relay connector started", "realm", os.Getenv("CONNECTOR_REALM"), "ingest_keys", len(ingest))
	c.Run(ctx)
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return health.Shutdown(shutdown)
}
