// Command ci-trust-scope-plan is the dry run for CI trusts and scope
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI trusts"): for
// each tenant with CI trust configurations, it counts what turning "Trust and
// add to scope" on would do for the trusts saved before it existed (entries
// to create or link), what the trusts that manage scope would change now,
// and the patterns the platform would refuse. Nothing is applied
// automatically: an administrator who may change scope turns it on per trust
// (audited, under the organization's approval rules). This command only
// reads (the connection is read-only), so it is safe on a live database.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	ci-trust-scope-plan                 every tenant with a trust
//	ci-trust-scope-plan -tenant <id>    one tenant
//	ci-trust-scope-plan -json           the report as JSON
//
// Exit status: 0 success, 1 the plan failed, 2 usage or connection error.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func main() {
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant with a CI trust)")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	codeHosts := flag.String("public-code-hosts-extra", os.Getenv("SCOPE_PUBLIC_CODE_HOSTS_EXTRA"),
		"comma-separated shared code hosts, as the API's SCOPE_PUBLIC_CODE_HOSTS_EXTRA")
	denyExtra := flag.String("deny-extra", os.Getenv("SCOPE_DENY_EXTRA"), "the API's SCOPE_DENY_EXTRA")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall time limit")
	flag.Parse()

	var tenants []shared.ID
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sqlDB, err := sql.Open("postgres", readOnlyURL(dbURL))
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer func() { _ = sqlDB.Close() }()
	if err := sqlDB.PingContext(ctx); err != nil {
		fail(2, "connect: "+err.Error())
	}

	reps, err := plan(ctx, &postgres.DB{DB: sqlDB}, tenants, splitList(*codeHosts), splitList(*denyExtra))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci-trust-scope-plan: "+err.Error())
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reps)
		return
	}
	fmt.Print(render(reps))
}

// plan wires the read-only services and runs the dry run.
func plan(ctx context.Context, db *postgres.DB, tenants []shared.ID, codeHosts, denyExtra []string) ([]cirunapp.ScopePlanTenant, error) {
	log := logger.NewNop()
	scope := scopeapp.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db),
		postgres.NewAssetRepository(db), log)
	scope.SetCITrustLinks(postgres.NewScopeCITrustLinkRepository(db))
	g, bad := scopedom.NewGuardrails(0, 0, denyExtra)
	if len(bad) > 0 {
		return nil, fmt.Errorf("-deny-extra has entries that are neither a domain nor an address range: %v", bad)
	}
	scope.SetGuardrails(g.WithPublicCodeHosts(codeHosts))
	ci := cirunapp.NewService(cirunapp.Deps{Repo: postgres.NewCIRunRepository(db)}, cirunapp.Config{}, log)
	ci.SetScopeLinker(scope)
	return ci.PlanScope(ctx, tenants)
}

// render prints one line per tenant and the totals.
func render(reps []cirunapp.ScopePlanTenant) string {
	var b strings.Builder
	actions := []string{scopedom.CITrustCreated, scopedom.CITrustLinked, scopedom.CITrustKept, scopedom.CITrustRetired,
		scopedom.CITrustRemoved, scopedom.CITrustRefused}
	line := func(m map[string]int) string {
		parts := make([]string, 0, len(actions))
		for _, a := range actions {
			parts = append(parts, fmt.Sprintf("%s %d", a, m[a]))
		}
		return strings.Join(parts, ", ")
	}
	managed, adoptable := map[string]int{}, map[string]int{}
	trusts, managedTrusts, adoptableTrusts := 0, 0, 0
	for _, r := range reps {
		trusts += r.Trusts
		managedTrusts += r.ManagedTrusts
		adoptableTrusts += r.AdoptableTrust
		for _, a := range actions {
			managed[a] += r.Managed[a]
			adoptable[a] += r.Adoptable[a]
		}
		fmt.Fprintf(&b, "tenant %s: trusts %d\n  managing scope %d: %s\n  if turned on %d: %s\n",
			r.TenantID, r.Trusts, r.ManagedTrusts, line(r.Managed), r.AdoptableTrust, line(r.Adoptable))
		refused := append([]string(nil), r.Refused...)
		sort.Strings(refused)
		for _, x := range refused {
			fmt.Fprintf(&b, "  refused %s\n", x)
		}
	}
	fmt.Fprintf(&b, "total (dry run): tenants %d, trusts %d\n  managing scope %d: %s\n  if turned on %d: %s\n",
		len(reps), trusts, managedTrusts, line(managed), adoptableTrusts, line(adoptable))
	return b.String()
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return ""
	}
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(get("DB_USER", "openctem"), os.Getenv("DB_PASSWORD")),
		Host:     host + ":" + get("DB_PORT", "5432"),
		Path:     "/" + get("DB_NAME", "openctem"),
		RawQuery: "sslmode=" + url.QueryEscape(get("DB_SSLMODE", "disable")),
	}
	return u.String()
}

// readOnlyURL makes every transaction of the connection read-only: the
// server refuses any write.
func readOnlyURL(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		q.Set("default_transaction_read_only", "on")
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " default_transaction_read_only=on"
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, "ci-trust-scope-plan: "+msg)
	os.Exit(code)
}
