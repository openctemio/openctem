package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/definition"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Tenant isolation of the definition repositories (RFC-044 §5.5, §10): a
// tenant reads global definitions and its own, writes only its own, and can
// never link its findings to another tenant's definition. Each negative case
// is checked with the other tenant's real ids.

func newTenantDef(t *testing.T, tenant shared.ID, externalID string) *definition.Definition {
	t.Helper()
	d, err := definition.NewTenantDefinition(tenant, "", definition.NamespaceNuclei, externalID, "panel "+externalID, definition.SourceReport)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDefinitionRepository_ReadsSeeGlobalAndOwn(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewDefinitionRepository(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	defA := newTenantDef(t, tA, "internal-admin")
	if err := repo.CreateTenantDefinition(ctx, tA, defA); err != nil {
		t.Fatalf("create A's definition: %v", err)
	}
	global := mustID(t, seedGlobalDefinition(ctx, t, db))

	for _, tenant := range []shared.ID{tA, tB} {
		if d, err := repo.GetByID(ctx, tenant, global); err != nil || !d.Scope().IsGlobal() {
			t.Errorf("global definition for %s: %v", tenant, err)
		}
	}
	got, err := repo.GetByID(ctx, tA, defA.ID())
	if err != nil || got.Scope().TenantID() != tA || got.ExternalID() != "internal-admin" || got.Kind() != definition.KindExposure {
		t.Fatalf("A reads its definition: %+v, %v", got, err)
	}
	if _, err := repo.GetByID(ctx, tB, defA.ID()); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("B reads A's definition: %v, want not found", err)
	}
	if _, err := repo.GetByID(ctx, shared.ID{}, global); !errors.Is(err, definition.ErrInvalid) {
		t.Errorf("no tenant: %v, want ErrInvalid", err)
	}

	// Resolve: through identifiers, the tenant's own only for that tenant.
	if d, err := repo.Resolve(ctx, tA, definition.NamespaceNuclei, "internal-admin"); err != nil || d.ID() != defA.ID() {
		t.Errorf("A resolves its template: %v", err)
	}
	if _, err := repo.Resolve(ctx, tB, definition.NamespaceNuclei, "internal-admin"); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("B resolves A's template: %v, want not found", err)
	}
	for name, list := range map[string]func(context.Context, shared.ID, shared.ID) error{
		"identifiers": func(c context.Context, tn, id shared.ID) error { _, err := repo.ListIdentifiers(c, tn, id); return err },
		"relations":   func(c context.Context, tn, id shared.ID) error { _, err := repo.ListRelations(c, tn, id); return err },
		"taxonomy":    func(c context.Context, tn, id shared.ID) error { _, err := repo.ListTaxonomy(c, tn, id); return err },
	} {
		if err := list(ctx, tB, defA.ID()); !errors.Is(err, definition.ErrNotFound) {
			t.Errorf("B lists the %s of A's definition: %v, want not found", name, err)
		}
		if err := list(ctx, tA, defA.ID()); err != nil {
			t.Errorf("A lists the %s of its definition: %v", name, err)
		}
	}
	idents, err := repo.ListIdentifiers(ctx, tA, defA.ID())
	if err != nil || len(idents) != 1 || !idents[0].IsPrimary || idents[0].Scope.TenantID() != tA {
		t.Errorf("A's definition identifiers: %+v, %v", idents, err)
	}
}

func TestDefinitionRepository_ResolveGlobalFirstAndAliases(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewDefinitionRepository(&DB{DB: db})
	tA := seedTestTenant(ctx, t, db)

	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})
	if err := NewVulnerabilityRepository(&DB{DB: db}).UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve)}); err != nil {
		t.Fatal(err)
	}
	d, err := repo.Resolve(ctx, tA, definition.NamespaceCVE, " "+cve+" ")
	if err != nil || d.CVEID() != cve {
		t.Fatalf("resolve a catalog CVE: %+v, %v", d, err)
	}

	// An alias asserted by OSV resolves to the same definition, also when a
	// report later asks for a stub under the alias.
	// The alias goes with the CVE definition on cleanup (ON DELETE CASCADE).
	const ghsa = "GHSA-jfh8-c2jp-5v3q"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO definition_identifiers (namespace, external_id, tenant_id, scope_tenant_id, definition_id, is_primary, asserted_by)
		VALUES ('GHSA', $1, NULL, $2, $3, FALSE, 'osv') ON CONFLICT DO NOTHING`, ghsa, definition.GlobalScopeKey, d.ID().String()); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.Resolve(ctx, tA, definition.NamespaceGHSA, ghsa); err != nil || got.ID() != d.ID() {
		t.Errorf("resolve the alias: %v, %v", got, err)
	}
	stub, _ := definition.NewGlobalStub(definition.NamespaceGHSA, ghsa)
	if id, err := repo.EnsureGlobalStub(ctx, stub); err != nil || id != d.ID() {
		t.Errorf("stub for a known alias: %s, %v; want the aliased definition %s", id, err, d.ID())
	}

	// A tenant template with the same id as a global one: the global wins.
	global := mustID(t, seedGlobalDefinition(ctx, t, db))
	gd, err := repo.GetByID(ctx, tA, global)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateTenantDefinition(ctx, tA, newTenantDef(t, tA, gd.ExternalID())); err != nil {
		t.Fatalf("tenant twin of a global template: %v", err)
	}
	if got, err := repo.Resolve(ctx, tA, definition.NamespaceNuclei, gd.ExternalID()); err != nil || got.ID() != global {
		t.Errorf("resolve prefers the global definition: %v, %v", got, err)
	}
}

func TestDefinitionRepository_EnsureGlobalStub(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewDefinitionRepository(&DB{DB: db})

	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})
	stub, err := definition.NewGlobalStub(definition.NamespaceCVE, cve)
	if err != nil {
		t.Fatal(err)
	}
	id, err := repo.EnsureGlobalStub(ctx, stub)
	if err != nil {
		t.Fatalf("create stub: %v", err)
	}
	// The CVE catalog API sees it like any CVE (cve_id is set).
	if v, err := NewVulnerabilityRepository(&DB{DB: db}).GetByCVE(ctx, cve); err != nil || v.ID() != id {
		t.Errorf("stub through the CVE catalog: %v", err)
	}
	again, _ := definition.NewGlobalStub(definition.NamespaceCVE, cve)
	if id2, err := repo.EnsureGlobalStub(ctx, again); err != nil || id2 != id {
		t.Errorf("second stub: %s, %v; want %s", id2, err, id)
	}

	// An existing catalog entry is returned unchanged.
	if _, err := db.ExecContext(ctx, `UPDATE vulnerabilities SET title = 'feed title' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	third, _ := definition.NewGlobalStub(definition.NamespaceCVE, cve)
	if _, err := repo.EnsureGlobalStub(ctx, third); err != nil {
		t.Fatal(err)
	}
	var title string
	if err := db.QueryRowContext(ctx, `SELECT title FROM vulnerabilities WHERE id = $1`, id.String()).Scan(&title); err != nil || title != "feed title" {
		t.Errorf("stub changed an existing entry: title %q, %v", title, err)
	}

	// Only identity stubs of advisory ids; nothing tenant-scoped.
	tA := seedTestTenant(ctx, t, db)
	if _, err := repo.EnsureGlobalStub(ctx, newTenantDef(t, tA, "x")); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("tenant definition as a global stub: %v", err)
	}
}

func TestDefinitionRepository_WritesOnlyOwnDefinitions(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewDefinitionRepository(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	defA := newTenantDef(t, tA, "a-rule")
	defB := newTenantDef(t, tB, "b-rule")
	for tenant, d := range map[shared.ID]*definition.Definition{tA: defA, tB: defB} {
		if err := repo.CreateTenantDefinition(ctx, tenant, d); err != nil {
			t.Fatal(err)
		}
	}
	global := mustID(t, seedGlobalDefinition(ctx, t, db))

	// Create: own scope only; one per (tenant, namespace, id); another tenant
	// may use the same id.
	if err := repo.CreateTenantDefinition(ctx, tB, newTenantDef(t, tA, "smuggled")); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("B creates a definition in A's scope: %v", err)
	}
	if err := repo.CreateTenantDefinition(ctx, tA, newTenantDef(t, tA, "a-rule")); !errors.Is(err, definition.ErrAlreadyExists) {
		t.Errorf("duplicate tenant definition: %v", err)
	}
	if err := repo.CreateTenantDefinition(ctx, tB, newTenantDef(t, tB, "a-rule")); err != nil {
		t.Errorf("B may name its own rule like A's: %v", err)
	}
	stub, _ := definition.NewGlobalStub(definition.NamespaceCVE, uniqueCVE())
	if err := repo.CreateTenantDefinition(ctx, tA, stub); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("tenant creates a global definition: %v", err)
	}

	alias := func(def shared.ID) definition.Identifier {
		return definition.Identifier{Namespace: definition.NamespaceNuclei, ExternalID: "alias-" + shared.NewID().String(),
			Scope: definition.TenantScope(tA), DefinitionID: def, AssertedBy: definition.SourceReport}
	}
	if err := repo.AddTenantIdentifier(ctx, tA, alias(defA.ID())); err != nil {
		t.Errorf("A aliases its definition: %v", err)
	}
	if err := repo.AddTenantIdentifier(ctx, tA, alias(global)); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("A aliases a global definition: %v", err)
	}
	if err := repo.AddTenantIdentifier(ctx, tA, alias(defB.ID())); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("A aliases B's definition: %v", err)
	}

	rel := func(from, to shared.ID) definition.Relation {
		// The caller's scopes are wrong on purpose: the repository reads them.
		return definition.Relation{FromID: from, FromScope: definition.Global(), ToID: to, ToScope: definition.Global(),
			Type: definition.RelationDetects, AssertedBy: definition.SourceReport}
	}
	if err := repo.AddTenantRelation(ctx, tA, rel(defA.ID(), global)); err != nil {
		t.Errorf("A's rule detects a global definition: %v", err)
	}
	if err := repo.AddTenantRelation(ctx, tA, rel(defA.ID(), defB.ID())); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("A relates to B's definition: %v", err)
	}
	rels, err := repo.ListRelations(ctx, tA, global)
	if err != nil || len(rels) != 1 || rels[0].FromScope.TenantID() != tA || !rels[0].ToScope.IsGlobal() {
		t.Errorf("A's view of the global definition's relations: %+v, %v", rels, err)
	}
	if rels, err := repo.ListRelations(ctx, tB, global); err != nil || len(rels) != 0 {
		t.Errorf("B sees A's private relation: %+v, %v", rels, err)
	}

	tax := func(def shared.ID) definition.TaxonomyLink {
		return definition.TaxonomyLink{DefinitionID: def, Namespace: "CWE", ExternalID: "CWE-79", AssertedBy: definition.SourceReport}
	}
	if err := repo.AddTenantTaxonomy(ctx, tA, tax(defA.ID())); err != nil {
		t.Errorf("A maps its rule to CWE-79: %v", err)
	}
	if err := repo.AddTenantTaxonomy(ctx, tA, tax(global)); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("A maps a global definition: %v", err)
	}
	if err := repo.AddTenantTaxonomy(ctx, tA, tax(defB.ID())); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("A maps B's definition: %v", err)
	}
	if links, err := repo.ListTaxonomy(ctx, tA, defA.ID()); err != nil || len(links) != 1 || links[0].ExternalID != "CWE-79" {
		t.Errorf("A's taxonomy links: %+v, %v", links, err)
	}
}

func TestFindingDefinitionRepository_ReplaceStaysInTenant(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	defs := NewDefinitionRepository(&DB{DB: db})
	repo := NewFindingDefinitionRepository(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	defA, defB := newTenantDef(t, tA, "a-tpl"), newTenantDef(t, tB, "b-tpl")
	if err := defs.CreateTenantDefinition(ctx, tA, defA); err != nil {
		t.Fatal(err)
	}
	if err := defs.CreateTenantDefinition(ctx, tB, defB); err != nil {
		t.Fatal(err)
	}
	global := mustID(t, seedGlobalDefinition(ctx, t, db))
	fA := mustID(t, seedPlainFinding(ctx, t, db, tA))
	fB := mustID(t, seedPlainFinding(ctx, t, db, tB))

	link := func(f shared.ID, def shared.ID, role definition.Role, ord int) definition.FindingLink {
		// DefinitionScope left empty (global): the repository must not trust it.
		return definition.FindingLink{FindingID: f, TenantID: tA, DefinitionID: def, Role: role, Ord: ord,
			AssertedBy: definition.LinkSourceReport}
	}
	readPrimary := func(f shared.ID) string {
		var s *string
		if err := db.QueryRowContext(ctx, `SELECT definition_id FROM findings WHERE id = $1`, f.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}

	good := []definition.FindingLink{link(fA, global, definition.RolePrimary, 0), link(fA, defA.ID(), definition.RoleDetectedBy, 1)}
	if err := repo.ReplaceForFinding(ctx, tA, fA, good); err != nil {
		t.Fatalf("link A's finding: %v", err)
	}
	if got := readPrimary(fA); got != global.String() {
		t.Errorf("definition_id = %q, want %s", got, global)
	}
	got, err := repo.ListByFinding(ctx, tA, fA)
	if err != nil || len(got) != 2 || got[1].DefinitionScope.TenantID() != tA || !got[0].DefinitionScope.IsGlobal() {
		t.Errorf("A's links: %+v, %v", got, err)
	}

	// Another tenant's definition: refused, nothing changed.
	bad := []definition.FindingLink{link(fA, defB.ID(), definition.RolePrimary, 0)}
	if err := repo.ReplaceForFinding(ctx, tA, fA, bad); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("link A's finding to B's definition: %v, want not found", err)
	}
	if got := readPrimary(fA); got != global.String() {
		t.Errorf("a refused replace changed definition_id to %q", got)
	}

	// Another tenant's finding.
	if err := repo.ReplaceForFinding(ctx, tA, fB, []definition.FindingLink{
		{FindingID: fB, TenantID: tA, DefinitionID: global, Role: definition.RolePrimary, AssertedBy: definition.LinkSourceReport},
	}); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("A links B's finding: %v, want not found", err)
	}
	if links, err := repo.ListByFinding(ctx, tB, fA); err != nil || len(links) != 0 {
		t.Errorf("B lists A's finding links: %+v, %v", links, err)
	}

	// Swap the primary, then clear.
	swapped := []definition.FindingLink{link(fA, defA.ID(), definition.RolePrimary, 0), link(fA, global, definition.RoleAdditional, 1)}
	if err := repo.ReplaceForFinding(ctx, tA, fA, swapped); err != nil {
		t.Fatalf("swap the primary: %v", err)
	}
	if got := readPrimary(fA); got != defA.ID().String() {
		t.Errorf("after swap definition_id = %q, want %s", got, defA.ID())
	}
	if err := repo.ReplaceForFinding(ctx, tA, fA, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := readPrimary(fA); got != "" {
		t.Errorf("after clear definition_id = %q", got)
	}
}
