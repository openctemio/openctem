# RFC-138: Web page monitoring (JS-only by default)

| | |
|---|---|
| Status | Partially implemented (2026-10-31): data model, ingest of fetch results, server-side change detection and diff, alerts, watch management API and the Attack surface › Page changes page. The fetch itself waits for the `monitor.web_content` capability in the capability taxonomy and its sensor implementation (§9). |
| Scope | api (`pkg/domain/pagemon`, `internal/app/pagemon`, `internal/app/ingest/web_content.go`, `/api/v1/easm/page-monitoring`, `page-monitoring` controller, exposure type `third_party_script_added`, one migration), web (Attack surface › Page changes) |
| Architecture | [easm.md §4o](../architecture/easm.md#4o-page-monitoring-partly-built) |
| Related | RFC-036 (EASM), RFC-046 (stage catalog), RFC-055 (capability taxonomy), RFC-056 (web endpoints), RFC-081 (web evidence), RFC-040 (mutual distrust sensor/platform) |

## 1. Summary

A web page or script that changes without anyone noticing is how card skimmers,
injected trackers and leaked endpoints reach production. The platform keeps,
per monitored URL, what the page loads and what its scripts contain, and says
when that changes:

- A **watch** is one URL of an organization's web origin (an `http_service`
  asset), chosen by a person (manual add) or accepted from suggestions (the
  origin's root page, login and admin pages and JS files the crawl found).
- **JS-only mode (default):** for a page, the set of scripts it loads (each
  external script's source, inline scripts by normalized hash) and, for each
  first-party script, its content hash, size and the URLs and paths found in
  it. **Full-page mode (opt-in):** the page's normalized visible text as well.
- A sensor **fetches** the watched URLs on the watch's cadence as an ordinary
  signed active job (capability `monitor.web_content`, tier T1) through the
  coverage dispatch path: scope gate, active-scan gate, zone routing, explicit
  URL list, sensor web scope and local policy. The sensor reports the
  response; it never executes it.
- The platform **normalizes, hashes and diffs server-side**, stores only what
  changed, and shows a diff: scripts added and removed, changed JS files with
  old and new size and hash, new URLs found in JS, and (full mode) lines added
  and removed.
- A **new third-party script domain** on a page is a `third_party_script_added`
  exposure (high: possible injection or skimming), announced through the EASM
  alert path. It resolves itself when the domain is gone from the page.

## 2. Goals and non-goals

Goals: detect script supply-chain changes on the organization's own pages with
little noise; one URL is one kind of act (GET the listed URL, nothing else);
everything the target sends is hostile; bounded storage per tenant; every read
filtered by tenant and data scope.

Non-goals: rendering pages or running their JavaScript (never, anywhere);
crawling (the crawl stage does that); fetching third-party hosts (a script on a
CDN is tracked by its source only; its content is not fetched because the host
is not the organization's); visual (screenshot) diffs; secret detection in
added lines (P2, with the secret rule content pack of research/349 §6.2).

## 3. Watches

| Field | Meaning |
|---|---|
| `url` | absolute http(s) URL, at most 2048 bytes, no user info, no fragment; unique per organization |
| `asset_id` | the `http_service` asset of the URL's origin (must exist in the organization and be in the caller's data scope) |
| `mode` | `js` (default) or `full` |
| `cadence_hours` | 6 to 168, default 24 |
| `ignore_patterns` | at most 10 RE2 patterns of at most 200 bytes; a script source, a URL found in JS or a text line that matches is left out before hashing |
| `source` | `manual`, `suggested`, or `derived` (a first-party script of a JS-mode page, added by the platform; at most 25 per page; removed when the page stops loading it) |
| `enabled`, `dynamic` | `dynamic`: three fetches in a row changed; its changes are recorded muted until a person edits the watch |
| state | `pending`, `ok`, `failed` (the fetch failed or the sensor reported an error status), `blocked` (the gate refused the URL, with its code), `waiting` (no sensor can run `monitor.web_content` yet) |

At most 200 watches per organization (derived ones included).

**Suggestions** (`GET .../suggestions`) list, for origins in the caller's data
scope, URLs that are not watched yet: each origin's root page, endpoints labelled
`auth:login`, endpoints that match the admin and authentication entries of the
web endpoint catalog, and script endpoints (JS files). Endpoints whose stored
path is a template (an identifier was replaced) are not suggested: the real
URL is not known.

## 4. Fetch: capability and scheduling

- Capability `monitor.web_content` (T1, in port `url`, no out port): GET each
  listed URL once, follow redirects on the same host only, read at most 5 MiB,
  report per URL. Default implementation `httpx` (the sensor's existing probe
  tool with response capture), so no new sensor binary.
- The `page-monitoring` controller runs every 10 minutes. Per organization with
  the Attack surface module and automatic coverage on, it takes due enabled
  watches (at most 100 URLs per pass, at most 10 per host per pass) and starts them through the coverage dispatch path
  (`scan.Service.StartCoverage`), which applies the scope gate and the
  active-scan ownership gate, routes by zone and signs one job per chunk of 20
  URLs with the explicit URL list. A refused URL is `blocked` with the gate's
  code and retried after 6 hours; a dispatched one is due again after its
  cadence. While the capability is unknown to the platform, watches stay
  `waiting` and nothing is sent.
- A JS-mode page's first-party scripts become derived watches, so their
  fetches pass the same gate as any URL. Third-party script hosts are never
  fetched.

## 5. Report contract (`web_content`)

The fetch result is the reserved asset property `web_content` on the report's
`http_service` (or `discovered_url`, `website`) asset: a list of captures.
Ingest takes it only for assets the report may change (RFC-040 §5.3) and never
stores it on the asset.

```json
{
  "url": "https://app.example.com/login",
  "final_url": "https://app.example.com/login/",
  "status_code": 200,
  "content_type": "text/html; charset=utf-8",
  "size": 183223,
  "sha256": "<hex SHA-256 of the bytes read>",
  "truncated": false,
  "body": "<response body as UTF-8 text, at most 512 KiB>",
  "body_truncated": false,
  "fetched_at": "2026-10-31T09:00:00Z"
}
```

Platform rules, whatever the sensor claims: at most 200 captures per report
and 24 MiB of bodies; a capture whose `url` is not an enabled watch of the
organization is dropped (a sensor cannot plant content for a URL nobody
watches); `final_url` on another host is dropped; every string is capped; a
body over 512 KiB is cut and flagged; invalid UTF-8 is replaced. Any tool that
writes this property is a valid implementation (third-party tools use the same
contract).

## 6. Normalization and change detection (server-side)

- **Kind:** `script` when the content type is JavaScript or the path ends in
  `.js`/`.mjs`; `html` for HTML; anything else `other` (hash only).
- **Script identity** (JS mode): the source resolved against the page URL,
  scheme and host lowercased, cache-buster query parameters removed (`v`,
  `ver`, `version`, `t`, `ts`, `_`, `cb`, `cachebust`, `rev`, `build`, `hash`)
  and build-hash file name parts replaced (`app.3f9a1c7e.js` → `app.*.js`), so
  a rebuilt bundle is a changed script, not one removed and one added.
  Inline scripts count by the hash of their text with nonces, long tokens
  (16+ token characters) and digit runs (6+) replaced.
- **First party:** the script host is the page host, shares its registrable
  domain (public suffix list), or is a domain or subdomain asset of the
  organization. Everything else is third party; a missing `integrity`
  attribute on a third-party script is recorded.
- **JS file:** the content hash is the SHA-256 the sensor reported (the body
  is not stored); URLs and absolute paths found in the body (RE2, at most 500,
  ignore patterns applied) are kept for the next diff.
- **Full mode:** visible text of the page (script, style and template contents
  dropped), one line per block, volatile tokens replaced as above, ignore
  patterns applied, masked like finding evidence, at most 256 KiB.
- **Content hash** = SHA-256 of the normalized form. Equal hash: the watch's
  last fetch time moves, nothing is stored. Different hash: a new snapshot and
  one change row with the diff (each list at most 100 items, text at most 200
  lines added and 200 removed). The first snapshot is the baseline: no change
  row, no alert.

### Severity rules

| Change | Severity |
|---|---|
| a third-party script from a domain the page did not load before | **high**, exposure `third_party_script_added` |
| a third-party script added from a domain already loaded | medium |
| a JS file's content changed; new URLs found in JS | low |
| a first-party script added or removed; an inline script changed; full-mode text changed; a third-party script removed | info |

The change row carries the highest severity of its parts. A `dynamic` watch's
changes are muted (listed, no alert) except the third-party domain rule,
whose exposure is deduplicated per page and domain.

## 7. Data model

- `web_watches` (tenant, asset, optional parent watch, URL, mode, cadence,
  ignore patterns, state, due and last-fetch times, change streak).
- `web_snapshots` (tenant, watch, fetch time, status, content type, size,
  body hash, content hash, kind, scripts JSON, URLs JSON, text): only on
  change; the last 5 per watch are kept.
- `web_changes` (tenant, watch, asset, time, severity, muted, summary counts,
  diff JSON): kept 180 days.

Every row carries `tenant_id`; snapshots and changes reference their watch by
`(tenant_id, watch_id)` and watches their asset by `(tenant_id, asset_id)`, so a
row can never point into another tenant. Deleting an asset deletes its
watches, snapshots and changes.

## 8. API and authorization

All under `/api/v1/easm/page-monitoring`, behind the Attack surface module:

| Route | Permission | Notes |
|---|---|---|
| `GET /watches` | `assets:read` | caller's data scope (watch asset) |
| `POST /watches` | `scans:write` | origin asset must exist and be in the caller's data scope; audited |
| `PUT /watches/{id}`, `DELETE /watches/{id}` | `scans:write` | same scope check; audited |
| `GET /suggestions` | `assets:read` | caller's data scope |
| `GET /changes`, `GET /changes/{id}` | `assets:read` | caller's data scope |

A watch, change or snapshot of another tenant or outside the caller's data
scope answers 404. Creating a watch schedules active traffic, hence the scan
write permission; the scope and ownership gates still decide every fetch.

## 9. Rollout

1. **Built:** data model, `web_content` ingest, normalization, diff, severity
   rules and exposure, controller (dispatch skipped while the capability is
   unknown), API, Attack surface › Page changes, retention sweep.
2. **Next (other repositories):** the `monitor.web_content` entry in the
   capability taxonomy; the response capture in the httpx mapping and the
   sensor's httpx wrapper (`-irr`, body capped, `web_content` property) when a
   job names the capability; then the stage catalog entry and the tool registry
   capability in the platform (one small change), after which watches leave
   `waiting`.
3. **Later:** secret rule content pack over added JS lines; conditional fetch
   (`If-None-Match`) to save bandwidth; coverage ledger rows per origin.

## 10. Threat model

| Threat | Control |
|---|---|
| Hostile content (script, HTML, decompression bomb) | never executed or rendered; the sensor reads at most 5 MiB (decompressed) and sends at most 512 KiB; the platform caps every field again, parses HTML with a tokenizer (no DOM, no script engine) and matches with RE2 (linear time); the diff is shown as text |
| A sensor plants content or alerts | only captures for enabled watches of the report's tenant are taken, only for assets the report may change; a forged change can only raise an alert on a URL the organization watches |
| SSRF / fetching what the organization does not own | no platform-side fetch; every fetch is a signed job with an explicit URL list that passed the scope and active-scan gates; third-party hosts are never fetched; the sensor's SSRF guard and web scope apply |
| Cross-tenant or out-of-scope reads | tenant on every query, composite foreign keys, data-scope filter on the watch's asset, 404 on a miss; tests with a second tenant and a restricted caller |
| Privacy of stored content | JS mode stores no page text; full mode stores masked normalized text (no bodies); retention 5 snapshots per watch and 180 days of changes; deleted with the asset or the organization |
| Storage growth | snapshots only on change, last 5 per watch, at most 200 watches per organization, capped lists and text |
| Load on the target | cadence at least 6 hours, at most 10 URLs per host per pass, the sensor's rate limits |
| Regex denial of service from ignore patterns | RE2 only, at most 10 patterns of 200 bytes, compiled at save time |
