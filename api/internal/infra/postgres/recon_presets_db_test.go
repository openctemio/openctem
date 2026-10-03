package postgres

import (
	"context"
	"testing"

	"github.com/lib/pq"
)

// Every step of an active system preset pipeline names a tool the catalog
// has (and a sensor image ships), with capabilities the catalog gives that
// tool: the queue-time step check (SecurityValidator.ValidateStepConfig)
// refuses anything else, so before migration 000270 no preset could run.
// Requires DATABASE_URL (CI applies every migration first).
func TestPresetPipelines_UseShippedTools(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()

	shipped := map[string]bool{
		"semgrep": true, "betterleaks": true, "trivy": true, "nuclei": true,
		"subfinder": true, "dnsx": true, "naabu": true, "httpx": true, "katana": true,
	}
	rows, err := db.QueryContext(ctx, `
		SELECT pt.name, ps.step_key, COALESCE(ps.tool, ''), COALESCE(ps.capabilities, '{}'),
		       COALESCE(t.capabilities, '{}'), t.id IS NOT NULL
		FROM pipeline_steps ps
		JOIN pipeline_templates pt ON pt.id = ps.pipeline_id
		LEFT JOIN tools t ON t.name = ps.tool AND t.tenant_id IS NULL AND t.is_active
		WHERE pt.is_system_template AND pt.is_active
		  AND pt.id::text LIKE 'a0000001-%'`) // the 000061 presets; Quick Scan picks its tool per run
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var tmpl, key, tool string
		var stepCaps, toolCaps []string
		var inCatalog bool
		if err := rows.Scan(&tmpl, &key, &tool, pq.Array(&stepCaps), pq.Array(&toolCaps), &inCatalog); err != nil {
			t.Fatal(err)
		}
		n++
		if tool == "" || !inCatalog || !shipped[tool] {
			t.Errorf("%s / %s: tool %q is not a shipped catalog tool", tmpl, key, tool)
			continue
		}
		allowed := map[string]bool{}
		for _, c := range toolCaps {
			allowed[c] = true
		}
		for _, c := range stepCaps {
			if !allowed[c] {
				t.Errorf("%s / %s: capability %q is not one of %s's %v", tmpl, key, c, tool, toolCaps)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no active system preset steps")
	}

	// Intrusive presets with unshipped tools are off (RFC-036 O3).
	var active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pipeline_templates
		WHERE id IN ('a0000001-0000-0000-0000-000000000004', 'a0000001-0000-0000-0000-000000000005') AND is_active`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Errorf("%d intrusive presets are active", active)
	}

	// The recon tools say what they scan.
	var bare int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM tools
		WHERE tenant_id IS NULL AND name IN ('subfinder', 'dnsx', 'naabu', 'httpx', 'katana')
		  AND (supported_targets = '{}' OR category_id IS NULL)`).Scan(&bare); err != nil {
		t.Fatal(err)
	}
	if bare != 0 {
		t.Errorf("%d recon tools have no target types or category", bare)
	}
}
