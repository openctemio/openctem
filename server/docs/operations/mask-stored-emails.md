# Masking e-mail addresses in stored findings

> **Applies to:** installations that stored findings before ingest masked
> e-mail addresses (`changelog.d/ingest-mask-email-addresses.md`). New
> findings and evidence are masked when they arrive; this runbook masks what
> was stored before.
>
> Design: `docs/architecture/finding-evidence.md` (Ingest flow, step 3).

The command is a mode of `refingerprint`, which ships in the API image:

```
refingerprint -mask-emails (-tenant <id>[,<id>...] | -all-tenants) [-apply] [-json] [-batch 500]
```

- It reads `DATABASE_URL` (or the server's `DB_*` variables), so it runs as is
  inside the API container.
- Without `-apply` it is a dry run on a read-only connection: it prints, per
  tenant, how many findings (per column) and evidence items it would change.
  The output holds counts and tenant ids only, never an address or a value.
- `-tenant` or `-all-tenants` is required (one of them). `-all-tenants` is
  every organization; the platform's reserved system tenant is not one.

## What it changes

- In findings a tool reported: the local part of every address in the
  descriptive columns becomes `***`, the domain is kept. Identifiers
  (fingerprints, identity and location keys, rule ids, file paths, links to
  tickets) are never changed. Findings a person reported (manual, pentest,
  bug bounty, red team) are left as written and counted as
  `human_findings_left`.
- In every evidence item: the same masking evidence gets when it is stored
  today. `evidence_unreadable` counts items in a shape this release does not
  read without loss; they are left unchanged.
- A finding's status is not changed. Its `updated_at` and row version move, as
  for any edit.

## Steps

1. Preview on the database, read-only, counts only (the query below).
2. Dry run: `refingerprint -mask-emails -all-tenants`.
3. Apply: `refingerprint -mask-emails -all-tenants -apply`. Each batch is a
   short transaction of its own; rows another transaction holds are skipped
   and counted as `remaining`.
4. Run the dry run again: every tenant reports 0 findings and 0 evidence
   items to change. Run step 3 again if `remaining` was not 0.

A run that stops halfway (crash, timeout) leaves whole batches done; run it
again. An applying run writes one `findings.emails_masked` audit entry in each
tenant it changed, with the counts and the run id.

Exit status: 0 success, 1 a tenant failed (the others still ran), 2 usage or
connection error.

## Preview query

Counts only: no values, no names, no tenant ids. The pattern is the one
`safetext.MaskEmails` uses (an address, or one URL-encoded with `%40`; version
strings such as `lib@1.2.3` and digests do not match). It also counts the
evidence bodies stored in base64, which the command decodes to look inside.

```sql
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '15min';
WITH re AS (
  SELECT '[A-Za-z0-9._%+-]+(@|%40)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\y'::text AS p
), f AS (
  SELECT f.tenant_id,
    COALESCE(f.source IN ('manual', 'pentest', 'bug_bounty', 'red_team')
      OR f.ingest_channel IS NOT DISTINCT FROM 'manual' OR f.pentest_campaign_id IS NOT NULL, false) AS human,
    f.title ~ re.p AS title, f.message ~ re.p AS message, f.description ~ re.p AS description,
    f.snippet ~ re.p AS snippet, f.context_snippet ~ re.p AS context_snippet,
    f.attack_prerequisites ~ re.p AS attack_prerequisites,
    f.misconfig_expected ~ re.p AS misconfig_expected, f.misconfig_actual ~ re.p AS misconfig_actual,
    f.scanner_output ~ re.p AS scanner_output, array_to_string(f.tags, ' ') ~ re.p AS tags,
    f.remediation::text ~ re.p AS remediation, f.metadata::text ~ re.p AS metadata,
    f.source_extra::text ~ re.p AS source_extra, f.type_details::text ~ re.p AS type_details,
    f.related_locations::text ~ re.p AS related_locations, f.stacks::text ~ re.p AS stacks
  FROM findings f, re
  WHERE strpos(concat_ws(' ', f.title, f.message, f.description, f.snippet, f.context_snippet,
      f.attack_prerequisites, f.misconfig_expected, f.misconfig_actual, f.scanner_output,
      array_to_string(f.tags, ' '), f.remediation::text, f.metadata::text, f.source_extra::text,
      f.type_details::text, f.related_locations::text, f.stacks::text), '@') > 0
     OR strpos(concat_ws(' ', f.title, f.message, f.description, f.snippet, f.context_snippet,
      f.attack_prerequisites, f.misconfig_expected, f.misconfig_actual, f.scanner_output,
      array_to_string(f.tags, ' '), f.remediation::text, f.metadata::text, f.source_extra::text,
      f.type_details::text, f.related_locations::text, f.stacks::text), '%40') > 0
), fa AS (
  SELECT * FROM f
  WHERE title OR message OR description OR snippet OR context_snippet OR attack_prerequisites
     OR misconfig_expected OR misconfig_actual OR scanner_output OR tags OR remediation OR metadata
     OR source_extra OR type_details OR related_locations OR stacks
), e AS (
  SELECT e.tenant_id, e.content::text ~ re.p AS addr,
    (e.content->'http'->'request'->>'body_encoding' = 'base64'
      OR e.content->'http'->'response'->>'body_encoding' = 'base64') AS b64
  FROM finding_evidence e, re
)
SELECT 'findings (tool-reported)' AS what, count(*) FILTER (WHERE NOT human) AS n FROM fa
UNION ALL SELECT 'findings (person-reported, left as written)', count(*) FILTER (WHERE human) FROM fa
UNION ALL SELECT 'column title', count(*) FILTER (WHERE NOT human AND title) FROM fa
UNION ALL SELECT 'column message', count(*) FILTER (WHERE NOT human AND message) FROM fa
UNION ALL SELECT 'column description', count(*) FILTER (WHERE NOT human AND description) FROM fa
UNION ALL SELECT 'column snippet', count(*) FILTER (WHERE NOT human AND snippet) FROM fa
UNION ALL SELECT 'column context_snippet', count(*) FILTER (WHERE NOT human AND context_snippet) FROM fa
UNION ALL SELECT 'column attack_prerequisites', count(*) FILTER (WHERE NOT human AND attack_prerequisites) FROM fa
UNION ALL SELECT 'column misconfig_expected', count(*) FILTER (WHERE NOT human AND misconfig_expected) FROM fa
UNION ALL SELECT 'column misconfig_actual', count(*) FILTER (WHERE NOT human AND misconfig_actual) FROM fa
UNION ALL SELECT 'column scanner_output', count(*) FILTER (WHERE NOT human AND scanner_output) FROM fa
UNION ALL SELECT 'column tags', count(*) FILTER (WHERE NOT human AND tags) FROM fa
UNION ALL SELECT 'column remediation (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND remediation) FROM fa
UNION ALL SELECT 'column metadata (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND metadata) FROM fa
UNION ALL SELECT 'column source_extra (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND source_extra) FROM fa
UNION ALL SELECT 'column type_details (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND type_details) FROM fa
UNION ALL SELECT 'column related_locations (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND related_locations) FROM fa
UNION ALL SELECT 'column stacks (jsonb, keys included)', count(*) FILTER (WHERE NOT human AND stacks) FROM fa
UNION ALL SELECT 'evidence items with an address', count(*) FILTER (WHERE addr) FROM e
UNION ALL SELECT 'evidence items with a base64 body (decoded by the command)', count(*) FILTER (WHERE b64) FROM e
UNION ALL SELECT 'tenants affected', count(DISTINCT tenant_id) FROM (
  SELECT tenant_id FROM fa WHERE NOT human UNION SELECT tenant_id FROM e WHERE addr) t;
ROLLBACK;
```

The command's own dry run is exact (it masks in memory with the same code as
ingest); this query is an estimate that needs no deployment: a jsonb column
counts an address in a key too, and the dry run does not.
