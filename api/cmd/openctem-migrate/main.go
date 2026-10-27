// Command openctem-migrate applies the OpenCTEM database migrations
// (docs/rfcs/RFC-130-migration-applied-set.md). It is the entrypoint of the
// migrations image, the all-in-one image's migration step and the binary
// install's openctem-migrate.service.
//
//	openctem-migrate -path DIR -database URL up
//	openctem-migrate -path DIR -database URL down N
//	openctem-migrate -path DIR -database URL force VERSION   (VERSION -1: only clear the dirty flag)
//	openctem-migrate -path DIR -database URL version
//	openctem-migrate -path DIR -database URL status
//
// The flags and commands up, down N, force N and version keep the form the
// deployments already pass. The password should come from PGPASSWORD, not
// the URL: a command line is readable by every user of the host.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq" // the "postgres" driver; reads PGPASSWORD and the other libpq variables

	"github.com/openctemio/openctem/api/internal/migrate"
	"github.com/openctemio/openctem/api/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: openctem-migrate -path DIR -database URL COMMAND

Commands:
  up          apply every migration the database has not applied, lowest version first
  down N      roll back the N most recently applied migrations
  force V     clear the dirty flag and record migration V as applied without running it
              (V = -1: only clear the dirty flag, so up runs the failed migration again)
  version     print the highest applied version (and "dirty" after a failed migration)
  status      print the applied count and every pending migration

Flags:
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("openctem-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	path := fs.String("path", "", "directory of the migration files")
	source := fs.String("source", "", "file://DIR, the same as -path")
	dbURL := fs.String("database", "", "postgres://user@host:port/db?sslmode=...")
	lockTimeout := fs.Uint("lock-timeout", 15, "seconds to wait for another run's migration lock")
	fs.Bool("verbose", false, "accepted for compatibility; progress is always printed")
	showVersion := fs.Bool("version", false, "print the version of this tool")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.Version)
		return 0
	}
	errf := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return 1
	}

	dir := *path
	if dir == "" && *source != "" {
		dir = strings.TrimPrefix(*source, "file://")
	}
	if dir == "" || *dbURL == "" || fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	migs, err := migrate.Load(dir)
	if err != nil {
		return errf("%v", err)
	}
	if len(migs) == 0 {
		return errf("no migrations in %s", dir)
	}
	dsn, err := cleanURL(*dbURL)
	if err != nil {
		return errf("%v", err)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return errf("open the database: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(2)

	r := &migrate.Runner{
		DB:          db,
		Migrations:  migs,
		LockTimeout: time.Duration(*lockTimeout) * time.Second,
		Logf:        func(f string, a ...any) { _, _ = fmt.Fprintf(stdout, f+"\n", a...) },
	}
	cmd, rest := fs.Arg(0), fs.Args()[1:]
	switch cmd {
	case "up":
		if _, err := r.Up(ctx); err != nil {
			return errf("%v", err)
		}
	case "down":
		if len(rest) != 1 {
			return errf("down needs the number of migrations to roll back (down 1)")
		}
		n, convErr := strconv.Atoi(rest[0])
		if convErr != nil || n <= 0 {
			return errf("down: %q is not a positive number", rest[0])
		}
		if _, err := r.Down(ctx, n); err != nil {
			return errf("%v", err)
		}
	case "force":
		if len(rest) != 1 {
			return errf("force needs a version")
		}
		v, convErr := strconv.ParseInt(rest[0], 10, 64)
		if convErr != nil || (v <= 0 && v != -1) {
			return errf("force: %q is not a migration version (or -1)", rest[0])
		}
		if err := r.Force(ctx, v); err != nil {
			return errf("%v", err)
		}
	case "version", "status":
		rep, err := migrate.Inspect(ctx, db, migs)
		if err != nil && !migrate.IsRefusal(err) {
			return errf("%v", err)
		}
		v := strconv.FormatInt(rep.Version, 10)
		if rep.Dirty {
			v += " (dirty)"
		}
		_, _ = fmt.Fprintln(stdout, v)
		if cmd == "status" {
			_, _ = fmt.Fprintf(stdout, "applied: %d\npending: %d\n", rep.Applied, len(rep.Pending))
			for _, m := range rep.Pending {
				_, _ = fmt.Fprintf(stdout, "  %s\n", m.Stem())
			}
			for _, u := range rep.Unknown {
				_, _ = fmt.Fprintf(stdout, "applied, not shipped here: %d\n", u)
			}
		}
		if err != nil {
			return errf("%v", err)
		}
	default:
		return errf("unknown command %q", cmd)
	}
	return 0
}

// cleanURL accepts postgres:// and postgresql:// URLs and drops the x-*
// query options the earlier tool understood (the driver would send them to
// the server as settings). Errors never repeat the URL: it may hold a
// password.
func cleanURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("-database is not a valid URL")
	}
	switch u.Scheme {
	case "postgres", "postgresql":
	default:
		return "", errors.New("-database must be a postgres:// URL")
	}
	q := u.Query()
	for k := range q {
		if strings.HasPrefix(k, "x-") {
			q.Del(k)
		}
	}
	u.Scheme = "postgres"
	u.RawQuery = q.Encode()
	return u.String(), nil
}
