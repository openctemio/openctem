### Security: a campaign needs a real scope before it counts or resolves

- A campaign's scope must name what is fixed: an asset, CVEs, linked
  findings, a tool or a fix key. A filter of only severities, sources,
  statuses or search text ("every critical finding") now tracks nothing and
  its resolve answers 400, instead of acting on the whole organization.
- Upgrade: the migration lists, in its output, every open campaign that will
  track nothing (`campaign scope: tenant … campaign … (name) …` and a total).
  To check before upgrading, read only:
  `SELECT tenant_id, id, name FROM remediation_campaigns WHERE status NOT IN ('completed','canceled') AND finding_filter <> '{}'::jsonb AND NOT (finding_filter ?| ARRAY['asset_id','cve_ids','cve_id','finding_ids','finding_id','tool_name','remediation_key'])`.
  Give each one an asset, CVEs, findings or a tool.
