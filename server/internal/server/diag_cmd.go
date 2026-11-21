package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/server/internal/app/systemstatus"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/diag"
	"github.com/openctemio/openctem/server/internal/diag/redact"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/infra/redis"
	"github.com/openctemio/openctem/server/internal/versions"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The operator's diagnosis commands (docs/operations/diagnose-and-get-support.md):
//
//	server doctor [--json] [--offline] [--timeout 1m]
//	server support-bundle [--since 24h] [--max-size 20M] [--output FILE|-] [--logs FILE|-] [--offline]
//
// They are commands of the server binary, so every way of installing the
// platform has them, and they run with the server's own settings: whoever can
// start a process in the server's container (or as its service user) can run
// them, nobody else. There is no HTTP route. They read; they change nothing.

const (
	cmdDoctor        = "doctor"
	cmdSupportBundle = "support-bundle"
)

func isDiagCommand(arg string) bool { return arg == cmdDoctor || arg == cmdSupportBundle }

// runDiagCommand runs one of the two commands and returns the exit code:
// doctor exits 0 only when no check failed; support-bundle exits 0 when the
// archive was written, whatever the doctor found (a bundle matters most when
// something is broken).
func runDiagCommand(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	offline := fs.Bool("offline", false, "Do not connect to the public URL to read its certificate")
	timeout := fs.Duration("timeout", 2*time.Minute, "Stop after this long")
	jsonOut := new(bool)
	since, maxSize, output, logs := new(time.Duration), new(string), new(string), new(string)
	if name == cmdDoctor {
		jsonOut = fs.Bool("json", false, "Print the result as JSON")
	} else {
		since = fs.Duration("since", diag.DefaultSince, "Keep log lines newer than this")
		maxSize = fs.String("max-size", "20M", "Largest archive to write (bytes, or with K, M or G); the oldest log lines are cut to fit")
		output = fs.String("output", "", "Where to write the archive; `-` writes it to standard output (default: openctem-support-<time>.tar.gz in the current directory)")
		logs = fs.String("logs", "", "Log file to include after masking; `-` reads standard input (default: no logs)")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "server %s: unexpected argument %q\n", name, fs.Arg(0))
		return 2
	}
	if *timeout <= 0 || *timeout > 30*time.Minute {
		_, _ = fmt.Fprintf(stderr, "server %s: --timeout must be between 1s and 30m\n", name)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	deps, closeDeps := diagDeps(*offline)
	defer closeDeps()

	if name == cmdDoctor {
		report := diag.Run(ctx, deps)
		if *jsonOut {
			if err := report.WriteJSON(stdout); err != nil {
				_, _ = fmt.Fprintf(stderr, "server doctor: %v\n", err)
				return 1
			}
		} else {
			report.WriteTable(stdout)
		}
		return report.ExitCode()
	}

	limit, err := parseSize(*maxSize)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "server support-bundle: --max-size: %v\n", err)
		return 2
	}
	return writeSupportBundle(ctx, deps, bundleOptions{
		since: *since, maxSize: limit, output: *output, logs: *logs, stdin: stdin, stdout: stdout, stderr: stderr,
	})
}

// diagDeps opens what the checks read through, the way the server does at
// start, and never stops on a failure: a failed step becomes a failed check.
func diagDeps(offline bool) (diag.Deps, func()) {
	var closers []func()
	d := diag.Deps{
		Getenv:          os.LookupEnv,
		MigrationsDir:   migrationsDirPath(),
		OwnsAuditTables: func(ctx context.Context, q diag.Querier) (bool, error) { return apiRoleOwnsAuditLog(ctx, q) },
	}
	if !offline {
		d.CertExpiry = servedCertExpiry
	}
	cfg, err := config.LoadWithExtensionKeys(buildExtensions.ConfigKeys())
	if err != nil {
		d.ConfigErr = err
		return d, func() {}
	}
	d.Config = cfg
	if err := versions.LoadExtraProducts(cfg.SensorConfig.ProductsFile); err == nil {
		d.SensorLatest, d.SensorMin = versions.SensorLatest(), versions.SensorMin()
	}

	// One connection: the commands read a few statements at a time.
	dbCfg := cfg.Database
	dbCfg.MaxOpenConns, dbCfg.MaxIdleConns = 2, 1
	if db, err := postgres.New(&dbCfg); err != nil {
		d.DBErr = err
	} else {
		d.DB = db.DB
		closers = append(closers, func() { _ = db.Close() })
	}

	// The clients log to nowhere: the commands' output is the report, and a
	// Redis that is down is one failed check, not a page of dial errors.
	quiet := logger.New(logger.Config{Level: "error", Output: io.Discard})
	goredis.SetLogger(silentRedisLog{})
	redisCfg := cfg.Redis
	redisCfg.MaxRetries = 0
	if rc, err := redis.New(&redisCfg, quiet); err != nil {
		d.RedisErr = err
	} else {
		d.PingRedis = rc.Ping
		closers = append(closers, func() { _ = rc.Close() })
	}

	collector := systemstatus.New(systemCollectorConfig(cfg), systemstatus.Deps{})
	d.System = collector.Collect
	return d, func() {
		for _, c := range closers {
			c()
		}
	}
}

// silentRedisLog drops the Redis client library's own log lines.
type silentRedisLog struct{}

func (silentRedisLog) Printf(context.Context, string, ...any) {}

// servedCertExpiry sends one HEAD request to the installation's own public
// origin (APP_URL, the operator's setting) with a normal, verifying TLS
// handshake, and returns when the served certificate expires. The client is
// the one the Health page probes the platform's own components with: no
// proxy, no redirects, a short timeout. When verification fails (an expired
// certificate, or one of a private CA this host does not trust) the
// connection is refused as always, and the expiry is read from the
// certificate the refusal carries: nothing is trusted for it.
func servedCertExpiry(ctx context.Context, hostPort string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+hostPort+"/", nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := httpsec.InternalProbeClient(5 * time.Second).Do(req)
	var refused *tls.CertificateVerificationError
	if errors.As(err, &refused) && len(refused.UnverifiedCertificates) > 0 {
		return refused.UnverifiedCertificates[0].NotAfter, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return time.Time{}, errors.New("no certificate presented")
	}
	return resp.TLS.PeerCertificates[0].NotAfter, nil
}

type bundleOptions struct {
	since   time.Duration
	maxSize int64
	output  string
	logs    string
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
}

func writeSupportBundle(ctx context.Context, deps diag.Deps, o bundleOptions) int {
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(o.stderr, "server support-bundle: "+format+"\n", a...)
		return 1
	}
	red, err := redact.New()
	if err != nil {
		return fail("%v", err)
	}
	var logs io.Reader
	switch o.logs {
	case "":
	case "-":
		logs = o.stdin
	default:
		f, err := os.Open(o.logs) //nolint:gosec // G304: a path the operator typed on their own command line
		if err != nil {
			return fail("cannot read the log file: %v", err)
		}
		defer func() { _ = f.Close() }()
		logs = f
	}

	var archive bytes.Buffer
	manifest, err := diag.WriteBundle(ctx, &archive, diag.BundleInput{
		Report:   diag.Run(ctx, deps),
		Config:   diag.EffectiveConfig(config.Registry(), os.LookupEnv),
		DB:       deps.DB,
		Logs:     logs,
		Since:    o.since,
		MaxSize:  o.maxSize,
		Redactor: red,
	})
	if err != nil {
		return fail("%v", err)
	}
	if int64(archive.Len()) > o.maxSize {
		return fail("the archive is %d bytes, over --max-size (%d); nothing was written", archive.Len(), o.maxSize)
	}

	where := o.output
	switch where {
	case "-":
		if _, err := o.stdout.Write(archive.Bytes()); err != nil {
			return fail("%v", err)
		}
		where = "standard output"
	default:
		if where == "" {
			where = "openctem-support-" + manifest.CreatedAt.Format("20060102T150405Z") + ".tar.gz"
		}
		// A new file only, readable by its owner only: an existing file is
		// never replaced.
		f, err := os.OpenFile(where, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a path the operator typed on their own command line
		if err != nil {
			return fail("cannot write the archive: %v (in a read-only container use `--output -` and redirect it to a file on the host)", err)
		}
		if _, err := f.Write(archive.Bytes()); err != nil {
			_ = f.Close()
			return fail("%v", err)
		}
		if err := f.Close(); err != nil {
			return fail("%v", err)
		}
	}

	// The summary goes to standard error, so `--output -` stays a clean
	// archive.
	w := o.stderr
	_, _ = fmt.Fprintln(w, "Support bundle contents:")
	for _, f := range manifest.Files {
		_, _ = fmt.Fprintf(w, "  %-26s %9d bytes  %s\n", f.Name, f.Bytes, f.About)
	}
	_, _ = fmt.Fprintf(w, "  %-26s             the list above with a SHA-256 of every file\n", "manifest.json")
	for _, n := range manifest.Notes {
		_, _ = fmt.Fprintf(w, "note: %s\n", n)
	}
	_, _ = fmt.Fprintf(w, "Never included: %s.\n", strings.Join(manifest.NeverIncluded, "; "))
	_, _ = fmt.Fprintf(w, "Wrote %d bytes to %s. Read it before you send it: tar -xzf <archive>, every file is plain text.\n", archive.Len(), where)
	return 0
}

// parseSize reads a byte count with an optional K, M or G suffix (powers of
// 1024).
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), "I")
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("not a size (examples: 500K, 20M, 1G)")
	}
	if n > diag.MaxMaxSize/mult {
		return 0, fmt.Errorf("at most %dM", diag.MaxMaxSize>>20)
	}
	n *= mult
	if n < diag.MinMaxSize {
		return 0, fmt.Errorf("at least %dK", diag.MinMaxSize>>10)
	}
	return n, nil
}
