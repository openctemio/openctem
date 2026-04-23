# Asset Source Priority — FAQ

> **Audience**: customer admins, customer success, support on-call
>
> **Scope**: the 10–12 questions we expect to hear. Not exhaustive — covers the ones we can predict from experience.
>
> **Related**: [Executive summary](./asset-source-priority-summary.md) · [RFC-003](./asset-source-priority.md)

## Rollout & safety

**Q: Will turning this on affect our existing assets?**

No. The migration only adds an index — it does not rewrite any asset data. Existing fields stay exactly where they are. From the first write *after* you opt in, the new priority rules apply to **that** write. Fields that no new source has touched remain unchanged.

**Q: If we configure priority wrongly, how do we undo it?**

Clear the priority list in Settings → Asset Sources, or `PUT /settings/asset-source` with an empty list. Within one 5-minute cache cycle, every ingest reverts to today's last-write-wins behavior. No data lost.

**Q: What happens to fields that were written before we opted in?**

They are treated as "unattributed". The next source to write that field becomes the owner, subject to the new priority. In practice this means the first few ingest rounds after opt-in will establish attribution naturally. If you want to pre-populate ownership (e.g. "Nessus owns everything today"), that is a Phase 2 feature (reprocessing endpoint) — not available in v1.

**Q: Can we test this in staging first?**

Yes. The feature is per-tenant — you can enable it on one tenant only, with full priority config, and leave production untouched. Recommended: spin up a staging tenant, run your real ingest pipelines against it for 24–48h, confirm the fields look right.

**Q: What if a data source is deleted — do my assets still reference it?**

Yes, with a flag. Historic attribution rows remain in `asset_sources` but marked `source_deleted=true`. UI renders them greyed-out with "(deleted source)". This preserves audit trail. If you need to fully purge, a separate admin endpoint can hard-delete — but default is preserve.

## Behavior & edge cases

**Q: Two scanners I both trust (both `High`) report different severities for the same CVE. Who wins?**

Inside the same trust bucket, it is last-write-wins by default (Q8 — pending customer confirmation). If you need deterministic tie-breaking, raise one of them to `Primary`. Phase 2 may add explicit sub-ordering inside a bucket.

**Q: Can I trust Source A for OS but trust Source B for CVEs?**

Not in v1. Trust level applies to the whole source, not per-field. This is the #1 Phase 2 candidate — we will revisit after 1–2 months of v1 usage to see if customers actually need it or if the simpler model is sufficient.

**Q: What if a trusted source goes silent — does my asset data go stale?**

The asset keeps the trusted source's last-known values (same as today — nothing overwrites them). Lower-trust sources that continue reporting will populate *new* fields the trusted source never touched, but will not overwrite existing trusted fields. If the trusted source is down for a long time, Settings → Asset Sources shows a "stale" indicator next to the source name.

**Q: Does this apply to findings, not just assets?**

Not in v1. Findings have their own dedup + merge rules (see `internal/app/finding/`). Phase 1 is asset-only. Finding-level source priority is a larger design — it touches severity, false-positive status, and remediation — and we want to land Phase 1 cleanly first.

**Q: What counts as "writing a field"?**

Any ingest path that populates `assets.properties.<key>` or a canonical top-level column (name, type, owner, severity...). Internal changes — retagging, manual status updates via UI — also count. The UI records you as the `Manual` source, so if Manual is ranked `Primary`, a human edit will always override a scanner later.

## Performance

**Q: Will this slow down ingest?**

Target: < 5% throughput regression. The priority gate adds one Redis-cached lookup per `(tenant, asset, source)` batch — not per field. Load test in Phase 1f enforces the 5% bar; we pull the feature behind a flag if it misses.

**Q: Does attribution bloat the database?**

Opt-in (`track_field_attribution: false` by default). When on, each asset carries roughly 50–100 bytes per field per source. A 10K-asset tenant with 3 sources and 20 tracked fields each = ~60MB. Capped at 500 field-writes per `(asset, source)` with oldest-dropped rotation. A background pruner (optional in Phase 1d) trims cold assets further.

## Integrations & APIs

**Q: Do I need to change my agent configuration?**

No. Agents register as `data_sources` already, and the priority is configured on the OpenCTEM side (Settings page or the dropdown on agent-create). Your agent code doesn't know or care about its trust level.

**Q: Can we configure trust via API / IaC?**

Yes:
```
PUT /api/v1/tenants/{id}/settings/asset-source
{
  "priority": ["uuid-nessus-prod", "uuid-manual", "uuid-aws"],
  "track_field_attribution": true
}
```
Permission required: `team:update`. Suitable for Terraform / Ansible pipelines.

**Q: Is there an SDK for this?**

Not in v1. The setting is admin-only and set infrequently (at onboarding + occasional reshuffles), so we did not prioritize SDK wrappers. Phase 2 candidate if demand appears.

## Comparisons to other tools

**Q: Is this like Splunk's "index priority" or Qualys's "source trust"?**

Similar intent, different scope. Splunk's priority is per-index and affects search ranking, not field-level merge. Qualys has a fixed source order (Qualys scanner always wins over uploaded data) without tenant config. Our model is closer to Splunk CIM's "authoritative source" pattern but operates at the field level during ingest, not at read time.

**Q: Why not just use a CMDB as the single source of truth?**

For customers that have one, we already integrate (ServiceNow CMDB, etc.) — treat it as a data source and rank it `Primary`. This RFC does not replace a CMDB; it lets you **make** any data source behave like one without calling it a CMDB.

## Escalation

**Q: Where do I report a bug with this feature?**

`asset_source_priority` label in the issue tracker. Include:
- Tenant ID (redact if sensitive)
- Sequence of scans / sources that led to the wrong value
- Output of `GET /assets/{id}?include=field_sources&include=source_skips`
  — that endpoint is the first-line debugging tool

The runbook (shipped with Phase 1f) lists common failure signatures and greps.

**Q: Who owns this feature long-term?**

Platform team. See CODEOWNERS entries on `pkg/domain/tenant/settings.go` and `internal/app/ingest/priority_gate.go` after Phase 1a merges.
