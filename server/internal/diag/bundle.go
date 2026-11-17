package diag

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/diag/redact"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/migrate"
	"github.com/openctemio/openctem/server/pkg/version"
)

// Limits of a bundle.
const (
	DefaultMaxSize = 20 << 20
	MinMaxSize     = 256 << 10
	MaxMaxSize     = 200 << 20
	DefaultSince   = 24 * time.Hour
	// MaxLogInput is how much log input is read at most.
	MaxLogInput = 2 << 30

	maxTables        = 2000
	maxIndexes       = 5000
	maxQueryShapes   = 50
	maxShapeLen      = 600
	longQueryDefault = 30 * time.Second
	archiveSlack     = 64 << 10
)

// BundleInput is everything a bundle is made from.
type BundleInput struct {
	// Report is the doctor's result (its details are masked here).
	Report Report
	// Config is the effective configuration (EffectiveConfig).
	Config []ConfigEntry
	// DB may be nil: the database files are then left out and the manifest
	// says so.
	DB *sql.DB
	// Logs is the log input, nil for none.
	Logs io.Reader
	// Since keeps log lines newer than this; lines that carry no time
	// follow the line before them.
	Since   time.Duration
	MaxSize int64

	Redactor         *redact.Redactor
	StatementTimeout time.Duration
	// LongQueryAfter is the age from which a running statement's shape is
	// listed (default 30s).
	LongQueryAfter time.Duration
	Now            func() time.Time
}

// File is one entry of the manifest.
type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	// About says what the file holds.
	About string `json:"about"`
}

// Manifest lists every file of a bundle (itself excepted) with its hash.
type Manifest struct {
	CreatedAt time.Time    `json:"created_at"`
	Build     version.Info `json:"build"`
	Files     []File       `json:"files"`
	// Notes say what was left out and why.
	Notes []string `json:"notes"`
	// NeverIncluded is the standing list of what no bundle holds.
	NeverIncluded []string `json:"never_included"`
}

// NeverIncluded is what no bundle holds.
var NeverIncluded = []string{
	"database rows of any table",
	"finding titles, descriptions and evidence",
	"asset names, addresses and host names",
	"user names and e-mail addresses",
	"organization names",
	"uploaded files",
	"keys, passwords, tokens and connection strings",
}

type bundleFile struct {
	name, about string
	data        []byte
}

// WriteBundle builds the bundle and writes it to w as a gzip-compressed tar
// archive. It returns the manifest, which is also the archive's last file.
func WriteBundle(ctx context.Context, w io.Writer, in BundleInput) (Manifest, error) {
	if in.Redactor == nil {
		return Manifest{}, errors.New("support bundle: no redactor")
	}
	if in.MaxSize == 0 {
		in.MaxSize = DefaultMaxSize
	}
	if in.MaxSize < MinMaxSize || in.MaxSize > MaxMaxSize {
		return Manifest{}, fmt.Errorf("support bundle: --max-size must be between %d and %d bytes", MinMaxSize, MaxMaxSize)
	}
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	created := now().UTC()
	m := Manifest{CreatedAt: created, Build: version.Get(), Notes: []string{}, NeverIncluded: NeverIncluded}

	var files []bundleFile
	add := func(name, about string, v any) {
		files = append(files, bundleFile{name: name, about: about, data: mustJSON(v)})
	}

	report := in.Report.Redacted(in.Redactor)
	var table bytes.Buffer
	report.WriteTable(&table)
	files = append(files, bundleFile{"doctor.txt", "the doctor's table, error details masked", table.Bytes()})
	add("doctor.json", "the doctor's result as JSON, error details masked", report)
	add("build.json", "version, commit, build time, loaded extensions and the Go runtime", buildInfo())
	add("config.json", "every registered setting as set / not set; values only of settings that cannot hold a secret, a name or an address", in.Config)

	if in.DB == nil {
		m.Notes = append(m.Notes, "database statistics and queue statistics left out: no database connection")
	} else {
		st := statsReader{db: in.DB, timeout: in.StatementTimeout, red: in.Redactor, longAfter: in.LongQueryAfter}
		if st.timeout <= 0 {
			st.timeout = 5 * time.Second
		}
		if st.longAfter <= 0 {
			st.longAfter = longQueryDefault
		}
		for _, part := range []struct {
			name, about string
			read        func(context.Context) (any, error)
		}{
			{"database/server.json", "PostgreSQL version, database size, connection counts", st.server},
			{"database/tables.json", "per table: size, estimated row count, dead rows, last vacuum and analyze, scan counts", st.tables},
			{"database/indexes.json", "per index: size, validity, scan count", st.indexes},
			{"database/activity.json", "sessions by state, and the shape of long-running statements with every literal removed", st.activity},
			{"database/migrations.json", "applied migrations: version, file name, time", st.migrations},
			{"queue.json", "queue depths, sensor counts by state and intelligence feed progress: counts and ages only", st.queue},
		} {
			v, err := part.read(ctx)
			if err != nil {
				m.Notes = append(m.Notes, part.name+" left out: "+in.Redactor.Message(err.Error()))
				continue
			}
			add(part.name, part.about, v)
		}
	}

	used := int64(len(readme))
	for _, f := range files {
		used += int64(len(f.data))
	}
	budget := in.MaxSize - used - archiveSlack
	switch {
	case in.Logs == nil:
		m.Notes = append(m.Notes, "logs left out: no log input was given (--logs)")
	case budget < 4<<10:
		m.Notes = append(m.Notes, "logs left out: --max-size leaves no room for them")
	default:
		since := in.Since
		if since <= 0 {
			since = DefaultSince
		}
		logs, note := redactLogs(ctx, in.Logs, in.Redactor, created.Add(-since), budget)
		files = append(files, bundleFile{"logs/server.log", "log lines of the chosen period, masked line by line", logs})
		m.Notes = append(m.Notes, note)
	}
	files = append(files, bundleFile{"README.txt", "what this archive is and how to inspect it", []byte(readme)})

	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		m.Files = append(m.Files, File{Name: f.name, Bytes: int64(len(f.data)), SHA256: hex.EncodeToString(sum[:]), About: f.about})
	}
	files = append(files, bundleFile{name: "manifest.json", data: mustJSON(m)})

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{Name: "openctem-support/" + f.name, Mode: 0o600, Size: int64(len(f.data)), ModTime: created, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return m, fmt.Errorf("support bundle: %w", err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return m, fmt.Errorf("support bundle: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return m, fmt.Errorf("support bundle: %w", err)
	}
	if err := gz.Close(); err != nil {
		return m, fmt.Errorf("support bundle: %w", err)
	}
	return m, nil
}

const readme = `OpenCTEM support bundle
=======================

This archive was written by "server support-bundle". It is meant to be sent
to someone who helps you and has no access to your installation.

Read it before you send it. Everything in it is plain text:

  tar -xzf <archive> && less openctem-support/*.txt openctem-support/*.json
  less openctem-support/logs/server.log

manifest.json lists every file with its size and SHA-256, what was left out
and why, and what no bundle ever holds.

Masked values look like [kind:1a2b3c4d]. The same value has the same mark
everywhere in this archive, so a problem can be followed through the logs
without the value itself. The marks are made with a random key that was
never stored: they cannot be turned back into the value, and they do not
match the marks of any other bundle.

If you see anything you do not want to share, delete that file (or the
line) before sending, or run the command again without --logs.
`

func mustJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(`{"error":"not encodable"}` + "\n")
	}
	return b.Bytes()
}

func buildInfo() map[string]any {
	return map[string]any{
		"build":      version.Get(),
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
	}
}

// redactLogs reads lines from in, drops those older than cutoff, and masks
// the newest ones that fit in budget bytes. Lines are masked newest first, so
// when ctx ends (--timeout) the lines that are missing are the oldest; the
// note says what happened. At most twice the budget of raw lines is held in
// memory.
func redactLogs(ctx context.Context, in io.Reader, red *redact.Redactor, cutoff time.Time, budget int64) ([]byte, string) {
	sc := bufio.NewScanner(io.LimitReader(in, MaxLogInput))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var raw []string
	var rawSize int64
	var read, old, cut int
	keep := true
	stopped := ""
	for sc.Scan() {
		if read%1024 == 0 && ctx.Err() != nil {
			stopped = "; reading stopped at the time limit (--timeout), later lines are missing"
			break
		}
		read++
		line := sc.Text()
		if at := redact.LineTime(line); !at.IsZero() {
			keep = !at.Before(cutoff)
		}
		if !keep {
			old++
			continue
		}
		raw = append(raw, line)
		rawSize += int64(len(line)) + 1
		for rawSize > 2*budget && len(raw) > 1 {
			rawSize -= int64(len(raw[0])) + 1
			raw[0] = ""
			raw = raw[1:]
			cut++
		}
	}
	if err := sc.Err(); err != nil {
		// A line over the scanner's limit ends the input: say so, keep what
		// was read.
		stopped += "; reading stopped early (" + red.Message(err.Error()) + ")"
	}

	masked := make([][]byte, 0, len(raw))
	var size int64
	for i := len(raw) - 1; i >= 0; i-- {
		if (len(raw)-i)%256 == 0 && ctx.Err() != nil {
			stopped += "; masking stopped at the time limit (--timeout), the oldest lines are missing"
			cut += i + 1
			break
		}
		line, _ := red.LogLine(raw[i])
		if size+int64(len(line))+1 > budget {
			cut += i + 1
			break
		}
		masked = append(masked, append([]byte(line), '\n'))
		size += int64(len(line)) + 1
	}
	for i, j := 0, len(masked)-1; i < j; i, j = i+1, j-1 {
		masked[i], masked[j] = masked[j], masked[i]
	}
	note := fmt.Sprintf("logs: %d lines read, %d older than the period, %d oldest lines cut to fit --max-size, %d kept%s",
		read, old, cut, len(masked), stopped)
	return bytes.Join(masked, nil), note
}

// ---------------------------------------------------------------------------
// Effective configuration
// ---------------------------------------------------------------------------

// ConfigEntry is one registered setting. Value is present only for a setting
// on the allow-list (shownValue).
type ConfigEntry struct {
	Name  string  `json:"name"`
	Group string  `json:"group"`
	Set   bool    `json:"set"`
	Value *string `json:"value,omitempty"`
}

// shownStrings are the free-text settings whose value is one of a few fixed
// words. Every other string, URL, path and list setting is shown as set or
// not set.
var shownStrings = map[string]bool{
	"APP_ENV": true, "LOG_LEVEL": true, "LOG_FORMAT": true, "AUTH_PROVIDER": true,
	"SIGNUP_MODE": true, "STORAGE_PROVIDER": true, "DB_SSLMODE": true,
}

// shownTypes are the setting types that cannot hold a secret, a name or an
// address.
var shownTypes = map[string]bool{"int": true, "bool": true, "duration": true, "float": true, "enum": true}

var plainValueRE = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,32}$`)

// shownValue reports whether a setting's value may be written: the setting
// is registered, is not a secret, is of a type or name on the allow-list, and
// the value is a short plain word or number.
func shownValue(v config.EnvVar, value string) bool {
	if v.Secret || (!shownTypes[v.Type] && !shownStrings[v.Name]) {
		return false
	}
	return plainValueRE.MatchString(value)
}

// EffectiveConfig lists every registered setting of the server and its tools
// as set or not set, with the value of those on the allow-list. A variable
// that is not registered is not listed at all: its name is not known to be
// safe.
func EffectiveConfig(reg *config.EnvRegistry, getenv func(string) (string, bool)) []ConfigEntry {
	out := make([]ConfigEntry, 0, len(reg.Vars))
	for _, v := range reg.Vars {
		if v.Component != "api" && v.Component != "tool" {
			continue
		}
		value, set := getenv(v.Name)
		e := ConfigEntry{Name: v.Name, Group: v.Group, Set: set && value != ""}
		if e.Set && shownValue(v, value) {
			val := value
			e.Value = &val
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------------------
// Database statistics: catalog and statistics views only, never a table's rows
// ---------------------------------------------------------------------------

type statsReader struct {
	db        *sql.DB
	timeout   time.Duration
	red       *redact.Redactor
	longAfter time.Duration
}

var schemaNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ident keeps a schema object's name when it is a plain identifier (the
// project's own are); any other name is masked.
func (s statsReader) ident(name string) string {
	if schemaNameRE.MatchString(name) {
		return name
	}
	return s.red.Value(name)
}

const userSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_'`

func nullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}

func (s statsReader) server(ctx context.Context) (any, error) {
	out := map[string]any{}
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		var ver, maxConn string
		var size, sessions int64
		var recovery bool
		if err := q.QueryRowContext(ctx, `
			SELECT current_setting('server_version'), current_setting('max_connections'),
			       pg_database_size(current_database()),
			       (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()),
			       pg_is_in_recovery()`).Scan(&ver, &maxConn, &size, &sessions, &recovery); err != nil {
			return err
		}
		out["server_version"], out["max_connections"] = safeName(ver), safeName(maxConn)
		out["database_bytes"], out["sessions"], out["in_recovery"] = size, sessions, recovery
		return nil
	})
	return out, err
}

func (s statsReader) tables(ctx context.Context) (any, error) {
	type table struct {
		Schema          string     `json:"schema"`
		Name            string     `json:"name"`
		EstimatedRows   int64      `json:"estimated_rows"`
		TotalBytes      int64      `json:"total_bytes"`
		TableBytes      int64      `json:"table_bytes"`
		LiveRows        int64      `json:"live_rows"`
		DeadRows        int64      `json:"dead_rows"`
		LastAutovacuum  *time.Time `json:"last_autovacuum,omitempty"`
		LastAutoanalyze *time.Time `json:"last_autoanalyze,omitempty"`
		SeqScans        int64      `json:"seq_scans"`
		IndexScans      int64      `json:"index_scans"`
	}
	out := []table{}
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		rows, err := q.QueryContext(ctx, `
			SELECT n.nspname, c.relname, GREATEST(c.reltuples, 0)::bigint, pg_total_relation_size(c.oid), pg_relation_size(c.oid),
			       COALESCE(st.n_live_tup, 0), COALESCE(st.n_dead_tup, 0), st.last_autovacuum, st.last_autoanalyze,
			       COALESCE(st.seq_scan, 0), COALESCE(st.idx_scan, 0)
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
			WHERE c.relkind IN ('r', 'p') AND `+userSchemas+`
			ORDER BY 4 DESC, 1, 2
			LIMIT $1`, maxTables)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var t table
			var vac, ana sql.NullTime
			if err := rows.Scan(&t.Schema, &t.Name, &t.EstimatedRows, &t.TotalBytes, &t.TableBytes, &t.LiveRows, &t.DeadRows,
				&vac, &ana, &t.SeqScans, &t.IndexScans); err != nil {
				return err
			}
			t.Schema, t.Name = s.ident(t.Schema), s.ident(t.Name)
			t.LastAutovacuum, t.LastAutoanalyze = nullTime(vac), nullTime(ana)
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

func (s statsReader) indexes(ctx context.Context) (any, error) {
	type index struct {
		Schema string `json:"schema"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Valid  bool   `json:"valid"`
		Ready  bool   `json:"ready"`
		Unique bool   `json:"unique"`
		Bytes  int64  `json:"bytes"`
		Scans  int64  `json:"scans"`
	}
	out := []index{}
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		rows, err := q.QueryContext(ctx, `
			SELECT n.nspname, t.relname, i.relname, x.indisvalid, x.indisready, x.indisunique,
			       pg_relation_size(i.oid), COALESCE(st.idx_scan, 0)
			FROM pg_index x
			JOIN pg_class i ON i.oid = x.indexrelid
			JOIN pg_class t ON t.oid = x.indrelid
			JOIN pg_namespace n ON n.oid = t.relnamespace
			LEFT JOIN pg_stat_user_indexes st ON st.indexrelid = i.oid
			WHERE `+userSchemas+`
			ORDER BY x.indisvalid, 7 DESC, 1, 3
			LIMIT $1`, maxIndexes)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ix index
			if err := rows.Scan(&ix.Schema, &ix.Table, &ix.Name, &ix.Valid, &ix.Ready, &ix.Unique, &ix.Bytes, &ix.Scans); err != nil {
				return err
			}
			ix.Schema, ix.Table, ix.Name = s.ident(ix.Schema), s.ident(ix.Table), s.ident(ix.Name)
			out = append(out, ix)
		}
		return rows.Err()
	})
	return out, err
}

func (s statsReader) activity(ctx context.Context) (any, error) {
	type long struct {
		State     string  `json:"state"`
		WaitEvent string  `json:"wait_event_type,omitempty"`
		Seconds   float64 `json:"seconds"`
		Shape     string  `json:"shape"`
	}
	states := map[string]int64{}
	longs := []long{}
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		rows, err := q.QueryContext(ctx, `
			SELECT COALESCE(state, 'background'), COALESCE(wait_event_type, ''),
			       COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - COALESCE(query_start, state_change)), 0)::float8,
			       COALESCE(query, '')
			FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid()
			ORDER BY 3 DESC`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var l long
			var query string
			if err := rows.Scan(&l.State, &l.WaitEvent, &l.Seconds, &query); err != nil {
				return err
			}
			l.State, l.WaitEvent = safeName(l.State), safeName(l.WaitEvent)
			states[l.State]++
			running := l.State == "active" || strings.HasPrefix(l.State, "idle in transaction")
			if running && l.Seconds >= s.longAfter.Seconds() && len(longs) < maxQueryShapes {
				l.Shape = s.red.Code(QueryShape(query))
				longs = append(longs, l)
			}
		}
		return rows.Err()
	})
	return map[string]any{"sessions_by_state": states, "long_running": longs, "long_running_after_seconds": s.longAfter.Seconds()}, err
}

func (s statsReader) migrations(ctx context.Context) (any, error) {
	type applied struct {
		Version   int64      `json:"version"`
		Name      string     `json:"name"`
		AppliedAt *time.Time `json:"applied_at,omitempty"`
	}
	out := map[string]any{}
	list := []applied{}
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		v, dirty, known, err := migrate.AppliedVersion(ctx, q)
		if err != nil {
			return err
		}
		out["version"], out["dirty"], out["known"] = v, dirty, known
		var has bool
		if err := q.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations_applied') IS NOT NULL`).Scan(&has); err != nil || !has {
			return err
		}
		rows, err := q.QueryContext(ctx, `SELECT version, name, applied_at FROM schema_migrations_applied ORDER BY version`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a applied
			var at sql.NullTime
			if err := rows.Scan(&a.Version, &a.Name, &at); err != nil {
				return err
			}
			a.Name, a.AppliedAt = s.ident(a.Name), nullTime(at)
			list = append(list, a)
		}
		return rows.Err()
	})
	out["applied"] = list
	return out, err
}

func (s statsReader) queue(ctx context.Context) (any, error) {
	var ops postgres.OpsSnapshot
	err := ReadOnly(ctx, s.db, s.timeout, func(q Querier) error {
		var err error
		ops, err = postgres.ReadOpsSnapshot(ctx, q)
		return err
	})
	if err != nil {
		return nil, err
	}
	// The snapshot is aggregate by construction; the few strings it carries
	// (versions sensors report, capability and tool names) are kept only
	// when they are plain words.
	for i := range ops.Sensors {
		ops.Sensors[i].SDKVersion = safeWord(ops.Sensors[i].SDKVersion, s.red)
		ops.Sensors[i].Health = safeWord(ops.Sensors[i].Health, s.red)
		ops.Sensors[i].ConfigHealth = safeWord(ops.Sensors[i].ConfigHealth, s.red)
	}
	for i := range ops.CommandQueue {
		d := &ops.CommandQueue[i]
		d.Stage, d.Tool, d.Class, d.Wait = safeWord(d.Stage, s.red), safeWord(d.Tool, s.red), safeWord(d.Class, s.red), safeWord(d.Wait, s.red)
	}
	for i := range ops.Feeds {
		ops.Feeds[i].Source = safeWord(ops.Feeds[i].Source, s.red)
	}
	return ops, nil
}

var plainWordRE = regexp.MustCompile(`^[A-Za-z0-9_.@:+-]{0,64}$`)

func safeWord(v string, red *redact.Redactor) string {
	if plainWordRE.MatchString(v) {
		return red.Code(v)
	}
	return red.Value(v)
}

// QueryShape reduces a SQL statement to its shape: every string literal,
// dollar-quoted body and number becomes "?", comments are dropped, and the
// result is cut to a fixed length. A statement cut off inside a literal (the
// server truncates long statements) loses everything from that literal on.
func QueryShape(q string) string {
	sh := shaper{q: q}
	for sh.i < len(q) && sh.b.Len() < maxShapeLen && sh.step() {
	}
	return strings.TrimSpace(sh.b.String())
}

// shaper walks a statement for QueryShape. prevWord says the last byte
// written belongs to a word, so a digit after it is part of that word ("t1",
// "$1") and not a number.
type shaper struct {
	q        string
	i        int
	b        strings.Builder
	prevWord bool
}

// step consumes one token and reports whether to go on (false: the rest of
// the statement is inside something that never closes).
func (sh *shaper) step() bool {
	q, i, n := sh.q, sh.i, len(sh.q)
	c := q[i]
	switch {
	case c == '\'':
		return sh.literal()
	case c == '$' && i+1 < n && (q[i+1] == '$' || isIdentStart(q[i+1])):
		return sh.dollar()
	case c == '-' && i+1 < n && q[i+1] == '-':
		nl := strings.IndexByte(q[i:], '\n')
		if nl < 0 {
			return false
		}
		sh.i += nl
	case c == '/' && i+1 < n && q[i+1] == '*':
		end := strings.Index(q[i+2:], "*/")
		if end < 0 {
			return false
		}
		sh.i += end + 4
		sh.space()
	case c == '"':
		return sh.quotedIdent()
	case c >= '0' && c <= '9' && !sh.prevWord:
		for sh.i < n && isNumberByte(q[sh.i]) {
			sh.i++
		}
		sh.b.WriteByte('?')
	case c == ' ' || c == '\n' || c == '\t' || c == '\r':
		sh.space()
		sh.i++
		sh.prevWord = false
	default:
		// Only ASCII passes: a statement's own words are ASCII, and
		// anything else is data that slipped through.
		if c < 0x20 || c > 0x7e {
			sh.b.WriteByte('?')
		} else {
			sh.b.WriteByte(c)
		}
		sh.prevWord = isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
		sh.i++
	}
	return true
}

func (sh *shaper) space() {
	if t := sh.b.String(); len(t) > 0 && t[len(t)-1] != ' ' {
		sh.b.WriteByte(' ')
	}
}

// literal replaces a string literal. An E'...' literal has backslash
// escapes; a plain one does not.
func (sh *shaper) literal() bool {
	q, i := sh.q, sh.i
	escapes := i > 0 && (q[i-1] == 'E' || q[i-1] == 'e') && (i < 2 || !isIdentStart(q[i-2]))
	end, ok := endOfString(q, i, escapes)
	sh.b.WriteByte('?')
	sh.i, sh.prevWord = end, false
	return ok
}

// dollar replaces a dollar-quoted body ($$...$$, $tag$...$tag$); a "$name"
// that opens no body is copied.
func (sh *shaper) dollar() bool {
	q, i := sh.q, sh.i
	tagEnd := strings.IndexByte(q[i+1:], '$')
	if tagEnd < 0 || !isTag(q[i+1:i+1+tagEnd]) {
		sh.b.WriteByte('$')
		sh.i++
		sh.prevWord = true
		return true
	}
	tag := q[i : i+tagEnd+2]
	closing := strings.Index(q[i+len(tag):], tag)
	sh.b.WriteByte('?')
	if closing < 0 {
		return false
	}
	sh.i, sh.prevWord = i+len(tag)+closing+len(tag), false
	return true
}

// quotedIdent copies a quoted identifier that is a plain name (schema, not
// data) and replaces any other.
func (sh *shaper) quotedIdent() bool {
	q, i := sh.q, sh.i
	end := strings.IndexByte(q[i+1:], '"')
	if end < 0 {
		return false
	}
	if name := q[i+1 : i+1+end]; schemaNameRE.MatchString(name) {
		sh.b.WriteString(`"` + name + `"`)
	} else {
		sh.b.WriteString(`"?"`)
	}
	sh.i, sh.prevWord = i+end+2, false
	return true
}

func isNumberByte(c byte) bool {
	return c == '.' || c == 'x' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// endOfString returns the index after the closing quote of the literal that
// starts at q[i] (” is an escape, and \' when escapes is set), and false
// when it never closes.
func endOfString(q string, i int, escapes bool) (int, bool) {
	for j := i + 1; j < len(q); j++ {
		switch q[j] {
		case '\\':
			if escapes {
				j++
			}
		case '\'':
			if j+1 < len(q) && q[j+1] == '\'' {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return len(q), false
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isTag(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isIdentStart(s[i]) && (i == 0 || s[i] < '0' || s[i] > '9') {
			return false
		}
	}
	return true
}
