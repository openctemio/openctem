package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// UpgradeCheckItem is one probe of the post-upgrade check for the
// agent → sensor rename (RFC-023 §9.5, migration 000230).
type UpgradeCheckItem struct {
	Area   string // "schema" or "data"
	What   string
	Count  int64
	Kept   bool // the old spelling is kept on purpose (history); never a failure
	Reason string
}

// Leftover reports whether the item is pre-rename vocabulary the migration
// should have converted.
func (i UpgradeCheckItem) Leftover() bool { return !i.Kept && i.Count > 0 }

type upgradeProbe struct {
	area, what string
	query      string
	kept       bool
	reason     string
	large      bool // scans a table that can be big; only in a full check
}

// The probes name the pre-rename vocabulary on purpose: they look for it.
var sensorRenameProbes = []upgradeProbe{
	{area: "schema", what: "tables, views or indexes still named agent*", query: `
		SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'i') AND c.relname LIKE '%agent%'`},
	{area: "schema", what: "columns still named *agent* (HTTP user_agent / actor_agent excluded)", query: `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name LIKE '%agent%'
		  AND column_name NOT IN ('user_agent', 'actor_agent')`},
	{area: "schema", what: "constraints still named *agent*", query: `
		SELECT count(*) FROM pg_constraint
		WHERE connamespace = 'public'::regnamespace AND conname LIKE '%agent%'`},
	{area: "schema", what: "triggers or RLS policies still named *agent*", query: `
		SELECT (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		        JOIN pg_namespace n ON n.oid = c.relnamespace
		        WHERE NOT t.tgisinternal AND n.nspname = 'public' AND t.tgname LIKE '%agent%')
		     + (SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND policyname LIKE '%agent%')`},
	{area: "schema", what: "functions whose body still names agent columns", query: `
		SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND (p.proname LIKE '%agent%' OR p.prosrc ~ '\m(agent_id|platform_agent_id|agents|agent_api_keys)\M')`},

	{area: "data", what: "permission catalog ids agents:*", query: `
		SELECT count(*) FROM permissions WHERE id LIKE 'agents:%'`},
	{area: "data", what: "role, group and permission-set grants of agents:*", query: `
		SELECT (SELECT count(*) FROM role_permissions WHERE permission_id LIKE 'agents:%')
		     + (SELECT count(*) FROM group_permissions WHERE permission_id LIKE 'agents:%')
		     + (SELECT count(*) FROM permission_set_items WHERE permission_id LIKE 'agents:%')`},
	{area: "data", what: "oct_ API keys with agents:* scopes", query: `
		SELECT count(*) FROM api_keys k
		WHERE EXISTS (SELECT 1 FROM unnest(k.scopes::text[]) s WHERE s LIKE 'agents:%')`},
	{area: "data", what: "sensor API keys with agent:* / admin:agents scopes", query: `
		SELECT count(*) FROM sensor_api_keys
		WHERE scopes::text[] && ARRAY['agent:heartbeat', 'agent:read', 'agent:write', 'admin:agents']`},
	{area: "data", what: "module id 'agents' (catalog or tenant toggles)", query: `
		SELECT (SELECT count(*) FROM modules WHERE id = 'agents' OR parent_module_id = 'agents')
		     + (SELECT count(*) FROM tenant_modules WHERE module_id = 'agents')`},
	{area: "data", what: "notification event types agent.* and references to them", query: `
		SELECT (SELECT count(*) FROM event_types WHERE id LIKE 'agent.%' OR category = 'agents')
		     + (SELECT count(*) FROM webhooks WHERE event_types::text[] && ARRAY['agent.offline', 'agent.error'])
		     + (SELECT count(*) FROM integration_notification_extensions
		        WHERE jsonb_typeof(enabled_event_types) = 'array' AND enabled_event_types ?| ARRAY['agent.offline', 'agent.error'])
		     + (SELECT count(*) FROM notification_preferences
		        WHERE jsonb_typeof(muted_types) = 'array' AND muted_types ?| ARRAY['agent.offline', 'agent.error'])`},
	{area: "data", what: "pipeline templates with settings.agent_preference", query: `
		SELECT count(*) FROM pipeline_templates WHERE settings ? 'agent_preference'`},
	{area: "data", what: "Tenable integrations with execution_mode 'agent' or an agent_id pin", query: `
		SELECT count(*) FROM integrations
		WHERE provider = 'tenable' AND (config ->> 'execution_mode' = 'agent' OR config ? 'agent_id')`},
	{area: "data", what: "assets / services with provenance 'agent'", large: true, query: `
		SELECT (SELECT count(*) FROM assets WHERE source_type = 'agent' OR discovery_source = 'agent')
		     + (SELECT count(*) FROM asset_services WHERE discovery_source = 'agent')`},
	{area: "data", what: "asset state history rows with source 'agent'", large: true,
		kept: true, reason: "asset_state_history is append-only; reads treat 'agent' as 'sensor'",
		query: `SELECT count(*) FROM asset_state_history WHERE source = 'agent'`},
	{area: "data", what: "audit rows written before the rename (agent.* / resource type agent)", large: true,
		kept: true, reason: "the audit log is hash-chained; history is never rewritten and reads treat both spellings as one family",
		query: `SELECT count(*) FROM audit_logs WHERE action LIKE 'agent.%' OR resource_type = 'agent'`},
}

// CheckSensorRename runs the post-upgrade probes. With full=false the probes
// that scan potentially large tables are skipped, which keeps it cheap enough
// to run at every server start.
func CheckSensorRename(ctx context.Context, db *sql.DB, full bool) ([]UpgradeCheckItem, error) {
	out := make([]UpgradeCheckItem, 0, len(sensorRenameProbes))
	for _, p := range sensorRenameProbes {
		if p.large && !full {
			continue
		}
		var n int64
		if err := db.QueryRowContext(ctx, p.query).Scan(&n); err != nil {
			return out, fmt.Errorf("upgrade check %q: %w", p.what, err)
		}
		out = append(out, UpgradeCheckItem{Area: p.area, What: p.what, Count: n, Kept: p.kept, Reason: p.reason})
	}
	return out, nil
}
