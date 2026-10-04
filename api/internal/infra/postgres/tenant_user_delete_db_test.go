package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Deleting an organization (DELETE FROM tenants) or a user (DELETE FROM users)
// used to fail on foreign keys that neither cascaded nor nulled, e.g.
// pentest_campaigns_tenant_id_fkey and suppression_rules_requested_by_fkey.
// Migration 000242 fixed the keys; the tests below keep it fixed:
//
//   - TestDeleteFKPolicy reads every foreign key to tenants and users from
//     pg_constraint, so a new table cannot quietly reintroduce a blocking key.
//   - TestDeleteTenantAndUser_EverySchemaTable seeds one row in every table
//     that has a tenant_id column, then deletes the user and the tenant.
//   - TestAssetStateHistory_AuditTriggers keeps the audit triggers protecting
//     direct edits while letting the two deletes through.
//
// DB-gated: they need DATABASE_URL pointing at a migrated *_test database.

// blockingFKAllowlist names foreign keys to tenants or users that may keep
// ON DELETE NO ACTION / RESTRICT. Each entry needs the reason the delete
// should be refused. It is empty on purpose: today no key has a reason to
// block deleting an organization or a person.
var blockingFKAllowlist = map[string]string{}

// auditTables keep their rows when the person who acted is deleted: their
// user references must be SET NULL, never CASCADE (nor blocking).
var auditTables = map[string]bool{
	"audit_logs":               true,
	"asset_state_history":      true,
	"exposure_state_history":   true,
	"finding_activities":       true,
	"suppression_rule_audit":   true,
	"finding_status_approvals": true,
}

// orphanAllowlist lists tables with a tenant_id column whose rows are meant
// to outlive the tenant, because they are audit evidence.
var orphanAllowlist = map[string]string{
	"audit_log_chain":                "hash chain of audit_logs; audit_logs keep their rows (tenant_id SET NULL) and the chain must stay verifiable",
	"audit_chain_rebaselines":        "record of an admin re-signing the audit chain; evidence, no FK to tenants by design",
	"audit_chain_rebaseline_entries": "hashes a chain rebaseline overwrote; evidence, no FK to tenants by design",
	"priority_class_audit_log":       "append-only priority audit trail; no FK to tenants by design",
}

func openDeleteTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	return db
}

type refFK struct {
	name    string
	table   string
	cols    []string
	notNull bool
	target  string
	delType string
}

func loadRefFKs(t *testing.T, db *sql.DB) []refFK {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.conname, c.conrelid::regclass::text, c.confrelid::regclass::text, c.confdeltype::text,
		       array_to_string(ARRAY(SELECT a.attname FROM unnest(c.conkey) k JOIN pg_attribute a
		                             ON a.attrelid = c.conrelid AND a.attnum = k), ','),
		       bool_and(a.attnotnull)
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
		WHERE c.contype = 'f' AND c.confrelid IN ('tenants'::regclass, 'users'::regclass)
		GROUP BY c.oid, c.conname, c.conrelid, c.confrelid, c.confdeltype, c.conkey
		ORDER BY 2, 1`)
	if err != nil {
		t.Fatalf("list FKs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []refFK
	for rows.Next() {
		var f refFK
		var cols string
		if err := rows.Scan(&f.name, &f.table, &f.target, &f.delType, &cols, &f.notNull); err != nil {
			t.Fatalf("scan FK: %v", err)
		}
		f.cols = strings.Split(cols, ",")
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate FKs: %v", err)
	}
	return out
}

func TestDeleteFKPolicy(t *testing.T) {
	db := openDeleteTestDB(t)
	fks := loadRefFKs(t, db)
	if len(fks) < 50 {
		t.Fatalf("found only %d FKs to tenants/users; is the schema migrated?", len(fks))
	}
	seen := map[string]bool{}
	for _, f := range fks {
		seen[f.name] = true
		blocking := f.delType == "a" || f.delType == "r"
		if blocking {
			if _, ok := blockingFKAllowlist[f.name]; !ok {
				t.Errorf("%s (%s.%s -> %s) is ON DELETE %s: deleting a %s fails while this row exists. "+
					"Use CASCADE for rows the %s owns, SET NULL for a who-did-it reference, "+
					"or add it to blockingFKAllowlist with the reason it must block",
					f.name, f.table, strings.Join(f.cols, ","), f.target, delTypeName(f.delType),
					strings.TrimSuffix(f.target, "s"), strings.TrimSuffix(f.target, "s"))
			}
			continue
		}
		if f.target == "users" && auditTables[f.table] && f.delType != "n" {
			t.Errorf("%s: audit table %s must keep its rows when a user is deleted (ON DELETE SET NULL), got %s",
				f.name, f.table, delTypeName(f.delType))
		}
		if f.delType == "n" && f.notNull {
			t.Errorf("%s is ON DELETE SET NULL but %s.%s is NOT NULL: the delete would fail",
				f.name, f.table, strings.Join(f.cols, ","))
		}
	}
	for name := range blockingFKAllowlist {
		if !seen[name] {
			t.Errorf("blockingFKAllowlist entry %s no longer exists; remove it", name)
		}
	}
}

func delTypeName(c string) string {
	switch c {
	case "a":
		return "NO ACTION"
	case "r":
		return "RESTRICT"
	case "c":
		return "CASCADE"
	case "n":
		return "SET NULL"
	case "d":
		return "SET DEFAULT"
	}
	return c
}

// --- generic schema seeder ---------------------------------------------------

type seedCol struct {
	name     string
	typ      string // format_type output
	notNull  bool
	hasDef   bool
	skip     bool // identity / generated
	enum     []string
	isArray  bool
	maxLen   int
	checkLit []string // literals from CHECK constraints that mention the column
}

type seedFK struct {
	cols    []string
	ref     string
	refCols []string
}

type seedTable struct {
	name  string
	cols  []seedCol
	fks   []seedFK
	pk    []string
	hasTn bool
}

type schemaSeeder struct {
	t        *testing.T
	ctx      context.Context
	tx       *sql.Tx
	tables   map[string]*seedTable
	rows     map[string]map[string]any // table -> seeded row
	tenantID string
	userID   string
	lastErr  map[string]string
	seq      int
}

// seedOverrides supplies values the generic rules cannot guess: cross-column
// CHECK constraints and formats. Keep it small; everything else is derived
// from the catalog so new tables are covered without touching this test.
var seedOverrides = map[string]func(s *schemaSeeder) map[string]any{
	"ai_triage_budgets": func(*schemaSeeder) map[string]any {
		return map[string]any{"period_start": "2026-01-01", "period_end": "2026-02-01"}
	},
	"asset_relationships": func(s *schemaSeeder) map[string]any {
		var second string
		if err := s.tx.QueryRowContext(s.ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'host') RETURNING id`,
			s.tenantID, s.uniq()).Scan(&second); err != nil {
			s.t.Fatalf("insert second asset: %v", err)
		}
		return map[string]any{"target_asset_id": second}
	},
	"audit_log_chain": func(*schemaSeeder) map[string]any {
		return map[string]any{"hash": strings.Repeat("ab", 32), "prev_hash": ""}
	},
	"audit_chain_rebaseline_entries": func(*schemaSeeder) map[string]any {
		h := strings.Repeat("ab", 32)
		return map[string]any{"old_hash": h, "old_prev_hash": "", "new_hash": h, "new_prev_hash": ""}
	},
	// fingerprint has a NOT LIKE CHECK; its literal is the excluded pattern.
	"finding_fingerprints": func(s *schemaSeeder) map[string]any { return map[string]any{"fingerprint": s.uniq()} },
	// target_version has a range CHECK.
	"finding_rekey_runs": func(*schemaSeeder) map[string]any { return map[string]any{"target_version": "2"} },
	// emoji has a length CHECK.
	"comment_reactions": func(*schemaSeeder) map[string]any { return map[string]any{"emoji": "👍"} },
	"scan_zones":        func(*schemaSeeder) map[string]any { return map[string]any{"is_default": "true"} },
	"sensors":           func(*schemaSeeder) map[string]any { return map[string]any{"status": "active"} },
	// type has a format CHECK, not a list of literals.
	"sensor_events": func(*schemaSeeder) map[string]any { return map[string]any{"type": "online"} },
	// digest has a format CHECK; manifest and ignored have type CHECKs.
	"sensor_manifests": func(*schemaSeeder) map[string]any {
		return map[string]any{"digest": "sha256:" + strings.Repeat("ab", 32), "manifest": "{}", "ignored": "[]"}
	},
}

var (
	litRe   = regexp.MustCompile(`'((?:[^']|'')*)'`)
	varchRe = regexp.MustCompile(`^(?:character varying|character|varchar)\((\d+)\)`)
)

func loadSchema(t *testing.T, ctx context.Context, tx *sql.Tx) map[string]*seedTable {
	t.Helper()
	tables := map[string]*seedTable{}
	loadSchemaColumns(t, ctx, tx, tables)
	loadSchemaConstraints(t, ctx, tx, tables)
	return tables
}

func loadSchemaColumns(t *testing.T, ctx context.Context, tx *sql.Tx, tables map[string]*seedTable) {
	t.Helper()
	rows, err := tx.QueryContext(ctx, `
		SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.atthasdef,
		       a.attidentity <> '' OR a.attgenerated <> '',
		       COALESCE((SELECT array_to_string(array_agg(e.enumlabel ORDER BY e.enumsortorder), chr(31))
		                 FROM pg_enum e WHERE e.enumtypid = a.atttypid), ''),
		       ty.typcategory = 'A'
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_type ty ON ty.oid = a.atttypid
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
		ORDER BY c.relname, a.attnum`)
	if err != nil {
		t.Fatalf("load columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tbl string
		var c seedCol
		var enum string
		if err := rows.Scan(&tbl, &c.name, &c.typ, &c.notNull, &c.hasDef, &c.skip, &enum, &c.isArray); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		if enum != "" {
			c.enum = strings.Split(enum, "\x1f")
		}
		if m := varchRe.FindStringSubmatch(c.typ); m != nil {
			c.maxLen, _ = strconv.Atoi(m[1])
		}
		st := tables[tbl]
		if st == nil {
			st = &seedTable{name: tbl}
			tables[tbl] = st
		}
		if c.name == "tenant_id" {
			st.hasTn = true
		}
		st.cols = append(st.cols, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
}

func loadSchemaConstraints(t *testing.T, ctx context.Context, tx *sql.Tx, tables map[string]*seedTable) {
	t.Helper()
	rows, err := tx.QueryContext(ctx, `
		SELECT c.conrelid::regclass::text, c.contype::text, c.confrelid::regclass::text,
		       array_to_string(ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n, i)
		            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.i), ','),
		       array_to_string(ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(n, i)
		            JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.i), ','),
		       pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class r ON r.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = r.relnamespace AND n.nspname = 'public'
		WHERE c.contype IN ('f', 'c', 'p') AND NOT r.relispartition`)
	if err != nil {
		t.Fatalf("load constraints: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tbl, typ, ref, cols, refCols, def string
		if err := rows.Scan(&tbl, &typ, &ref, &cols, &refCols, &def); err != nil {
			t.Fatalf("scan constraint: %v", err)
		}
		st := tables[tbl]
		if st == nil {
			continue
		}
		switch typ {
		case "p":
			st.pk = strings.Split(cols, ",")
		case "f":
			st.fks = append(st.fks, seedFK{cols: strings.Split(cols, ","), ref: ref, refCols: strings.Split(refCols, ",")})
		case "c":
			for i := range st.cols {
				col := &st.cols[i]
				if !regexp.MustCompile(`\b` + regexp.QuoteMeta(col.name) + `\b`).MatchString(def) {
					continue
				}
				for _, m := range litRe.FindAllStringSubmatch(def, -1) {
					col.checkLit = append(col.checkLit, strings.ReplaceAll(m[1], "''", "'"))
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate constraints: %v", err)
	}
}

func (s *schemaSeeder) uniq() string {
	s.seq++
	return fmt.Sprintf("s%s%d", strings.ReplaceAll(s.tenantID, "-", ""), s.seq)
}

// value returns a literal for a column that has no FK, for the given attempt.
func (s *schemaSeeder) value(c seedCol, attempt int) any {
	if len(c.enum) > 0 {
		return c.enum[attempt%len(c.enum)]
	}
	if c.isArray {
		return "{}"
	}
	if len(c.checkLit) > 0 && (strings.Contains(c.typ, "char") || c.typ == "text") {
		return c.checkLit[attempt%len(c.checkLit)]
	}
	switch {
	case c.typ == "uuid":
		return shared.NewID().String()
	case c.typ == "text" || strings.HasPrefix(c.typ, "character") || c.typ == "citext":
		v := s.uniq()
		if c.maxLen > 0 && len(v) > c.maxLen {
			v = v[len(v)-c.maxLen:]
		}
		return v
	}
	if v, ok := scalarValue(c.typ, attempt); ok {
		return v
	}
	return s.uniq()
}

// scalarLiterals are the literals for non-text scalar types; a second
// entry is tried on the retry (CHECKs that want true or a JSON array).
var scalarLiterals = map[string][]string{
	"smallint":                    {"1"},
	"integer":                     {"1"},
	"bigint":                      {"1"},
	"real":                        {"1"},
	"double precision":            {"1"},
	"boolean":                     {"false", "true"},
	"date":                        {"today"},
	"interval":                    {"1 hour"},
	"jsonb":                       {"{}", "[]"},
	"json":                        {"{}", "[]"},
	"inet":                        {"10.0.0.1"},
	"cidr":                        {"10.0.0.0/24"},
	"macaddr":                     {"00:00:00:00:00:01"},
	"bytea":                       {`\x00`},
	"tsvector":                    {""},
	"timestamp with time zone":    {"now"},
	"timestamp without time zone": {"now"},
	"time without time zone":      {"00:00"},
	"time with time zone":         {"00:00"},
}

// scalarValue returns a literal for a non-text scalar type.
func scalarValue(typ string, attempt int) (string, bool) {
	if strings.HasPrefix(typ, "numeric") {
		typ = "integer"
	}
	if i := strings.Index(typ, "("); i > 0 && strings.HasPrefix(typ, "time") {
		typ = typ[:i] + typ[strings.Index(typ, ")")+1:]
	}
	v, ok := scalarLiterals[typ]
	if !ok {
		return "", false
	}
	return v[attempt%len(v)], true
}

// refRow returns the row a FK should point at, or nil when none exists yet.
func (s *schemaSeeder) refRow(table string) map[string]any {
	switch table {
	case "tenants":
		return map[string]any{"id": s.tenantID}
	case "users":
		return map[string]any{"id": s.userID}
	}
	return s.rows[table]
}

func (s *schemaSeeder) existingGlobalRow(table string) map[string]any {
	var raw []byte
	err := s.tx.QueryRowContext(s.ctx, fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t LIMIT 1`, quoteIdent(table))).Scan(&raw)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func quoteIdent(s string) string {
	if strings.Contains(s, ".") {
		parts := strings.SplitN(s, ".", 2)
		return quoteIdent(parts[0]) + "." + quoteIdent(parts[1])
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func asText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// trySeed inserts one row into st. strict=true refuses to leave a nullable
// FK to an unseeded table empty, so the first passes wire up as many
// relations (and so as many cascade paths) as possible.
func (s *schemaSeeder) trySeed(st *seedTable, strict bool) bool {
	fkVal, ok := s.fkValues(st, strict)
	if !ok {
		return false
	}
	if o := seedOverrides[st.name]; o != nil {
		for k, v := range o(s) {
			fkVal[k] = v
		}
	}
	for attempt := 0; attempt < 4; attempt++ {
		if s.insertRow(st, fkVal, attempt) {
			delete(s.lastErr, st.name)
			return true
		}
	}
	return false
}

// fkValues picks, for every FK of st, the seeded row it points at. It
// reports false when a required (or, in strict mode, any) target is missing.
func (s *schemaSeeder) fkValues(st *seedTable, strict bool) (map[string]any, bool) {
	fkVal := map[string]any{}
	for _, fk := range st.fks {
		if fk.ref == st.name {
			continue // self reference: leave NULL
		}
		if st.name == "admin_users" && fk.ref == "users" {
			// A platform administrator cannot also be an organization member
			// (000226 trigger), and the seeded user is one: leave user_id NULL,
			// an API-key administrator identity.
			continue
		}
		row := s.refRow(fk.ref)
		if row == nil {
			if ref, ok := s.tables[fk.ref]; ok && !ref.hasTn {
				row = s.existingGlobalRow(fk.ref)
				if row == nil && s.seedGlobal(ref) {
					row = s.rows[fk.ref]
				}
			}
		}
		required := false
		for _, c := range fk.cols {
			for _, col := range st.cols {
				if col.name == c && col.notNull && !col.hasDef {
					required = true
				}
			}
		}
		if row == nil {
			if required || strict {
				s.lastErr[st.name] = "waiting for " + fk.ref
				return nil, false
			}
			continue
		}
		for i, c := range fk.cols {
			if c == "tenant_id" {
				continue
			}
			if v, ok := row[fk.refCols[i]]; ok && v != nil {
				if _, set := fkVal[c]; !set {
					fkVal[c] = v
				}
			}
		}
	}
	return fkVal, true
}

// insertRow tries one INSERT into st under a savepoint and records the row.
func (s *schemaSeeder) insertRow(st *seedTable, fkVal map[string]any, attempt int) bool {
	var cols, exprs []string
	var args []any
	for _, c := range st.cols {
		if c.skip {
			continue
		}
		var v any
		switch {
		case c.name == "tenant_id" && st.hasTn:
			v = s.tenantID
		case fkVal[c.name] != nil:
			v = asText(fkVal[c.name])
		case c.notNull && !c.hasDef:
			v = s.value(c, attempt)
		default:
			continue
		}
		args = append(args, v)
		cols = append(cols, quoteIdent(c.name))
		exprs = append(exprs, fmt.Sprintf("$%d::%s", len(args), c.typ))
	}
	q := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) RETURNING to_jsonb(%s.*)`,
		quoteIdent(st.name), strings.Join(cols, ","), strings.Join(exprs, ","), quoteIdent(st.name))
	if len(cols) == 0 {
		q = fmt.Sprintf(`INSERT INTO %s DEFAULT VALUES RETURNING to_jsonb(%s.*)`, quoteIdent(st.name), quoteIdent(st.name))
	}
	if _, err := s.tx.ExecContext(s.ctx, "SAVEPOINT seed_row"); err != nil {
		s.t.Fatalf("savepoint: %v", err)
	}
	var raw []byte
	if err := s.tx.QueryRowContext(s.ctx, q, args...).Scan(&raw); err != nil {
		s.lastErr[st.name] = err.Error()
		if _, rerr := s.tx.ExecContext(s.ctx, "ROLLBACK TO SAVEPOINT seed_row"); rerr != nil {
			s.t.Fatalf("rollback to savepoint: %v", rerr)
		}
		return false
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	s.rows[st.name] = m
	return true
}

func (s *schemaSeeder) seedGlobal(st *seedTable) bool {
	if _, busy := s.lastErr["global:"+st.name]; busy {
		return false // already being seeded higher up (FK cycle)
	}
	s.lastErr["global:"+st.name] = "in progress"
	ok := s.trySeed(st, false)
	delete(s.lastErr, "global:"+st.name)
	return ok
}

// seedAll seeds one row in every tenant-scoped table, plus any global row
// they need. It returns the tables it could not seed.
func (s *schemaSeeder) seedAll() []string {
	var pending []*seedTable
	for _, st := range s.tables {
		if st.hasTn && st.name != "tenants" {
			pending = append(pending, st)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].name < pending[j].name })
	for _, strict := range []bool{true, false} {
		for progress := true; progress; {
			progress = false
			var next []*seedTable
			for _, st := range pending {
				if s.trySeed(st, strict) {
					progress = true
				} else {
					next = append(next, st)
				}
			}
			pending = next
		}
	}
	out := make([]string, 0, len(pending))
	for _, st := range pending {
		out = append(out, st.name+": "+s.lastErr[st.name])
	}
	return out
}

func (s *schemaSeeder) rowExists(table string, row map[string]any) (exists bool, cols map[string]any) {
	st := s.tables[table]
	if len(st.pk) == 0 {
		return false, nil
	}
	var conds []string
	var args []any
	for _, c := range st.pk {
		args = append(args, asText(row[c]))
		conds = append(conds, fmt.Sprintf("%s::text = $%d", quoteIdent(c), len(args)))
	}
	var raw []byte
	err := s.tx.QueryRowContext(s.ctx, fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t WHERE %s`,
		quoteIdent(table), strings.Join(conds, " AND ")), args...).Scan(&raw)
	if err != nil {
		return false, nil
	}
	_ = json.Unmarshal(raw, &cols)
	return true, cols
}

func TestDeleteTenantAndUser_EverySchemaTable(t *testing.T) {
	db := openDeleteTestDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }() // nothing is left behind

	s := &schemaSeeder{t: t, ctx: ctx, tx: tx, rows: map[string]map[string]any{}, lastErr: map[string]string{}}
	s.tenantID = shared.NewID().String()
	s.userID = shared.NewID().String()
	mustExecTx(t, tx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'fk-delete-test', $2)`, s.tenantID, "fkdel-"+s.tenantID)
	mustExecTx(t, tx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'FK Delete Test')`, s.userID, "fkdel-"+s.userID+"@example.test")
	s.tables = loadSchema(t, ctx, tx)

	if failed := s.seedAll(); len(failed) > 0 {
		t.Fatalf("could not seed %d tenant-scoped tables (extend the seeder):\n  %s", len(failed), strings.Join(failed, "\n  "))
	}
	seeded := 0
	for name, st := range s.tables {
		if st.hasTn && s.rows[name] != nil {
			seeded++
		}
	}
	t.Logf("seeded %d tenant-scoped tables", seeded)

	// A repository with a branch finding (migration 000238's cascade path):
	// make sure the seeded finding really sits on the seeded branch.
	if s.rows["findings"] == nil || s.rows["findings"]["branch_id"] == nil {
		t.Fatalf("seeded finding has no branch_id; the repository-branch cascade is not exercised")
	}

	userFKs := loadRefFKs(t, db)

	t.Run("delete user keeps authored rows", func(t *testing.T) {
		mustExecTx(t, tx, "SAVEPOINT del_user")
		defer mustExecTx(t, tx, "ROLLBACK TO SAVEPOINT del_user")
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, s.userID); err != nil {
			t.Fatalf("DELETE FROM users: %v", err)
		}
		checked := 0
		for _, f := range userFKs {
			if f.target != "users" || f.delType != "n" {
				continue
			}
			row := s.rows[f.table]
			if row == nil || asText(row[f.cols[0]]) != s.userID {
				continue
			}
			if hasUserCascade(userFKs, f.table) {
				continue // the row itself belongs to the user
			}
			exists, now := s.rowExists(f.table, row)
			if len(s.tables[f.table].pk) == 0 {
				continue
			}
			if !exists {
				// Gone through another cascade path (e.g. its parent row
				// belonged to the user); audit rows must never go.
				if auditTables[f.table] {
					t.Errorf("%s row was deleted with the user; audit rows must stay", f.table)
				}
				continue
			}
			if now[f.cols[0]] != nil {
				t.Errorf("%s.%s still %v after the user was deleted", f.table, f.cols[0], now[f.cols[0]])
			}
			checked++
		}
		if checked < 20 {
			t.Errorf("only %d who-did-it references were checked; the seeder lost coverage", checked)
		}
		for _, tbl := range []string{"asset_state_history", "suppression_rule_audit", "audit_logs", "finding_status_approvals", "suppression_rules", "attachments"} {
			if s.rows[tbl] == nil {
				continue
			}
			if ok, _ := s.rowExists(tbl, s.rows[tbl]); !ok {
				t.Errorf("%s row disappeared with its author", tbl)
			}
		}
	})

	t.Run("delete tenant leaves no orphans", func(t *testing.T) {
		mustExecTx(t, tx, "SAVEPOINT del_tenant")
		defer mustExecTx(t, tx, "ROLLBACK TO SAVEPOINT del_tenant")
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, s.tenantID); err != nil {
			t.Fatalf("DELETE FROM tenants: %v", err)
		}
		names := make([]string, 0, len(s.tables))
		for name := range s.tables {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !s.tables[name].hasTn {
				continue
			}
			var n int
			if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id::text = $1`, quoteIdent(name)), s.tenantID).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", name, err)
			}
			if _, keep := orphanAllowlist[name]; keep {
				continue
			}
			if n != 0 {
				t.Errorf("%s still has %d rows of the deleted tenant", name, n)
			}
		}
	})
}

func hasUserCascade(fks []refFK, table string) bool {
	for _, f := range fks {
		if f.table == table && f.target == "users" && f.delType == "c" {
			return true
		}
	}
	return false
}

func TestAssetStateHistory_AuditTriggers(t *testing.T) {
	db := openDeleteTestDB(t)
	ctx := context.Background()

	// seed returns a tenant with an asset, a user, and one fresh history row
	// written by that user.
	seed := func(t *testing.T, tx *sql.Tx) (tenantID, userID, historyID string) {
		t.Helper()
		tenantID = shared.NewID().String()
		userID = shared.NewID().String()
		mustExecTx(t, tx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'audit-trigger', $2)`, tenantID, "audtrg-"+tenantID)
		mustExecTx(t, tx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'Audit Trigger')`, userID, "audtrg-"+userID+"@example.test")
		var assetID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'host') RETURNING id`,
			tenantID, "h-"+tenantID).Scan(&assetID); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO asset_state_history (tenant_id, asset_id, change_type, source, changed_by, changed_at)
			VALUES ($1, $2, 'appeared', 'manual', $3, now()) RETURNING id`, tenantID, assetID, userID).Scan(&historyID); err != nil {
			t.Fatalf("insert history: %v", err)
		}
		return tenantID, userID, historyID
	}
	inTx := func(t *testing.T, fn func(tx *sql.Tx)) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		fn(tx)
	}
	mustFail := func(t *testing.T, tx *sql.Tx, want, q string, args ...any) {
		t.Helper()
		mustExecTx(t, tx, "SAVEPOINT expect_fail")
		_, err := tx.ExecContext(ctx, q, args...)
		mustExecTx(t, tx, "ROLLBACK TO SAVEPOINT expect_fail")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got err %v, want it to contain %q", q, err, want)
		}
	}

	t.Run("direct delete of a recent row is refused", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			_, _, id := seed(t, tx)
			mustFail(t, tx, "less than 30 days old", `DELETE FROM asset_state_history WHERE id = $1`, id)
		})
	})
	t.Run("direct update is refused", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			_, _, id := seed(t, tx)
			mustFail(t, tx, "immutable", `UPDATE asset_state_history SET reason = 'edited' WHERE id = $1`, id)
		})
	})
	t.Run("clearing changed_by of an existing user is refused", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			_, _, id := seed(t, tx)
			mustFail(t, tx, "immutable", `UPDATE asset_state_history SET changed_by = NULL WHERE id = $1`, id)
		})
	})
	t.Run("deleting the tenant removes its recent history", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			tenantID, _, id := seed(t, tx)
			mustExecTx(t, tx, `DELETE FROM tenants WHERE id = $1`, tenantID)
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM asset_state_history WHERE id = $1`, id).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != 0 {
				t.Fatalf("history row survived its tenant")
			}
		})
	})
	// Postgres fires the tenant's cascade triggers in trigger-name order,
	// which follows OIDs. On a fresh database assets go first, so the asset
	// check of migration 000169 happened to let the history through; on an
	// older database (or after the assets FK is recreated) the history row
	// is reached while its asset still exists. Recreate the assets FK to get
	// that order and check the delete does not depend on it.
	t.Run("deleting the tenant does not depend on cascade order", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			// The ALTER locks assets and tenants, which concurrently running
			// packages use all the time: take both up front, never waiting
			// while holding one, or the ALTER deadlocks with them.
			testdb.LockForDDL(t, ctx, tx, "tenants", "assets")
			mustExecTx(t, tx, `ALTER TABLE assets DROP CONSTRAINT assets_tenant_id_fkey,
				ADD CONSTRAINT assets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE`)
			tenantID, _, _ := seed(t, tx)
			mustExecTx(t, tx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		})
	})
	t.Run("deleting the user keeps the row with no actor", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			_, userID, id := seed(t, tx)
			mustExecTx(t, tx, `DELETE FROM users WHERE id = $1`, userID)
			var changedBy sql.NullString
			var changeType string
			if err := tx.QueryRowContext(ctx, `SELECT changed_by, change_type FROM asset_state_history WHERE id = $1`, id).Scan(&changedBy, &changeType); err != nil {
				t.Fatalf("history row gone after deleting its user: %v", err)
			}
			if changedBy.Valid || changeType != "appeared" {
				t.Fatalf("got changed_by=%v change_type=%s, want NULL/appeared", changedBy, changeType)
			}
		})
	})
}

// TestDeletedAuthor_RowsStillLoad: suppression_rules.requested_by,
// finding_status_approvals.requested_by and attachments.uploaded_by were
// NOT NULL and are SET NULL now. The repositories must still read such rows
// (they scanned into a plain string, which fails on NULL).
func TestDeletedAuthor_RowsStillLoad(t *testing.T) {
	db := openDeleteTestDB(t)
	ctx := context.Background()
	pdb := &DB{DB: db}

	tenantID := shared.NewID()
	userID := shared.NewID()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	mustExec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'deleted-author', $2)`, tenantID.String(), "delauth-"+tenantID.String())
	t.Cleanup(func() {
		// Deleting the tenant is itself part of what migration 000242 fixed.
		if _, err := db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()); err != nil {
			t.Errorf("cleanup tenant: %v", err)
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID.String())
	})
	mustExec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Deleted Author')`, userID.String(), "delauth-"+userID.String()+"@example.test")

	var findingID, ruleID, approvalID, attachmentID string
	if err := db.QueryRowContext(ctx, `INSERT INTO findings (tenant_id, source, tool_name, message, severity, fingerprint)
		VALUES ($1, 'sast', 'semgrep', 'x', 'high', $2) RETURNING id`, tenantID.String(), "fp-"+tenantID.String()).Scan(&findingID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO suppression_rules (tenant_id, name, rule_id, suppression_type, status, requested_by)
		VALUES ($1, 'r', 'rule-1', 'false_positive', 'pending', $2) RETURNING id`, tenantID.String(), userID.String()).Scan(&ruleID); err != nil {
		t.Fatalf("insert suppression rule: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by, justification)
		VALUES ($1, $2, 'false_positive', $3, 'because') RETURNING id`, tenantID.String(), findingID, userID.String()).Scan(&approvalID); err != nil {
		t.Fatalf("insert approval: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO attachments (tenant_id, filename, content_type, size, storage_key, uploaded_by, context_type, context_id)
		VALUES ($1, 'e.txt', 'text/plain', 1, $2, $3, 'finding', $4) RETURNING id`, tenantID.String(), "k-"+tenantID.String(), userID.String(), findingID).Scan(&attachmentID); err != nil {
		t.Fatalf("insert attachment: %v", err)
	}

	mustExec(`DELETE FROM users WHERE id = $1`, userID.String())

	rule, err := NewSuppressionRepository(pdb).FindByID(ctx, tenantID, shared.MustIDFromString(ruleID))
	if err != nil || rule == nil {
		t.Fatalf("load suppression rule: %v", err)
	}
	if !rule.RequestedBy().IsZero() {
		t.Errorf("rule requested_by = %s, want zero", rule.RequestedBy())
	}
	rules, err := NewSuppressionRepository(pdb).FindPendingByTenant(ctx, tenantID)
	if err != nil || len(rules) != 1 {
		t.Fatalf("list suppression rules: %d, %v", len(rules), err)
	}
	approval, err := NewFindingApprovalRepository(pdb).GetByTenantAndID(ctx, tenantID, shared.MustIDFromString(approvalID))
	if err != nil {
		t.Fatalf("load approval: %v", err)
	}
	if !approval.RequestedBy.IsZero() {
		t.Errorf("approval requested_by = %s, want zero", approval.RequestedBy)
	}
	attRepo := NewAttachmentRepository(pdb)
	att, err := attRepo.GetByID(ctx, tenantID, shared.MustIDFromString(attachmentID))
	if err != nil {
		t.Fatalf("load attachment: %v", err)
	}
	if !att.UploadedBy().IsZero() {
		t.Errorf("attachment uploaded_by = %s, want zero", att.UploadedBy())
	}
	if list, err := attRepo.ListByContext(ctx, tenantID, "finding", findingID); err != nil || len(list) != 1 {
		t.Fatalf("list attachments: %d, %v", len(list), err)
	}
}
