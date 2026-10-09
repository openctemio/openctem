// Command openctem-signer is the job-signing service: it signs the jobs the
// API hands to sensors with a key the API never holds, on a Unix socket only.
// Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.6 and
// docs/architecture/job-signing.md.
//
//	openctem-signer keygen -out /keys/signer.pem   create a key (0400), print its id
//	openctem-signer pubkey                          print the key id and public key
//	openctem-signer verify-log                      check the signing log's chain
//	openctem-signer [serve]                         serve on SIGNER_SOCKET
//
// Environment: SIGNER_KEY_FILE, SIGNER_SOCKET, SIGNER_STATE_DIR,
// SIGNER_TENANT_RATE, SIGNER_TENANT_BURST, SIGNER_SENSOR_RATE,
// SIGNER_SENSOR_BURST.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/openctemio/openctem/api/internal/signer"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openctem-signer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "keygen":
		return keygen(args)
	case "pubkey":
		priv, err := signer.LoadKey(os.Getenv("SIGNER_KEY_FILE"))
		if err != nil {
			return err
		}
		pub, _ := priv.Public().(ed25519.PublicKey)
		printKey(pub)
		return nil
	case "verify-log":
		return verifyLog()
	case "serve":
		return serve()
	default:
		return fmt.Errorf("unknown command %q (keygen, pubkey, verify-log, serve)", cmd)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path of the new key file (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	pub, err := signer.GenerateKey(*out)
	if err != nil {
		return err
	}
	printKey(pub)
	return nil
}

func printKey(pub ed25519.PublicKey) {
	k := jobsign.NewPublicKey(pub)
	fmt.Printf("keyid: %s\nalgorithm: %s\npublic_key: %s\n", k.KeyID, k.Algorithm, k.PublicKey)
}

func verifyLog() error {
	dir := os.Getenv("SIGNER_STATE_DIR")
	if dir == "" {
		return errors.New("SIGNER_STATE_DIR is required")
	}
	f, err := os.Open(filepath.Join(dir, "signing.log")) // #nosec G304 -- operator-supplied state directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	last, n, err := signer.VerifyLog(f)
	if err != nil {
		return err
	}
	fmt.Printf("signing log OK: %d entries, head %s\n", n, last)
	return nil
}

func serve() error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service", "openctem-signer")
	keyFile, socket, stateDir := os.Getenv("SIGNER_KEY_FILE"), os.Getenv("SIGNER_SOCKET"), os.Getenv("SIGNER_STATE_DIR")
	if keyFile == "" || socket == "" || stateDir == "" {
		return errors.New("SIGNER_KEY_FILE, SIGNER_SOCKET and SIGNER_STATE_DIR are required")
	}
	key, err := signer.LoadKey(keyFile)
	if err != nil {
		return err
	}
	cfg := signer.Config{Key: key, StateDir: stateDir, Logger: logger}
	if cfg.TenantRate, err = envFloat("SIGNER_TENANT_RATE"); err != nil {
		return err
	}
	if cfg.TenantBurst, err = envInt("SIGNER_TENANT_BURST"); err != nil {
		return err
	}
	if cfg.SensorRate, err = envFloat("SIGNER_SENSOR_RATE"); err != nil {
		return err
	}
	if cfg.SensorBurst, err = envInt("SIGNER_SENSOR_BURST"); err != nil {
		return err
	}
	svc, err := signer.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	// The socket is created owner and group only (0660) from the start.
	syscall.Umask(0o117)
	ln, err := signer.ListenUnix(socket)
	if err != nil {
		return err
	}
	srv := signer.NewHTTPServer(svc.Handler())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	logger.Info("signer listening", "socket", socket, "keyid", svc.KeyID())
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}
	return nil
}

func envFloat(name string) (float64, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("%s must be a positive number", name)
	}
	return f, nil
}

func envInt(name string) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}
