# RFC-081: Web evidence and screenshots of web assets

| | |
|---|---|
| Status | Accepted (2026-10-11); platform side implemented, sensor `screenshot` tool in the sensor repository |
| Scope | api (`pkg/domain/webevidence`, `internal/app/webevidence`, ingest step 10, `asset_web_evidence` migration, two routes, retention controller, EASM setting), web (asset page card, monitoring card switch), sensor (optional `screenshot` tool image) |
| Architecture | [easm.md §4j](../architecture/easm.md#4j-web-evidence-and-screenshots-built) |
| Related | RFC-036 (EASM; O7 retention: screenshots 30 days), RFC-040 (mutual distrust; results are hostile input), RFC-057 / finding-evidence.md (masking), research/106 §10 decision 1 |

## 1. Summary

Triage of a web asset needs to see it: where it redirects, what it answers,
what the page shows. Sensors already report status, title and server; the
response body and any picture of the page were dropped.

- A sensor attaches **captures** to a web asset: URL, final URL, status,
  title, server, content type, the first 4 KiB of the response (masked) and,
  optionally, a **screenshot**.
- The platform validates every field, masks the snippet, re-encodes the
  screenshot as a fresh PNG and keeps it in the organization's file storage
  for **30 days** (decision O7). The newest 5 captures per asset are kept.
- Screenshots are **off by default** twice over: the sensor tool ships as a
  separate optional image (headless Chromium is large and a browser is a big
  attack surface), and the organization must turn on
  `web_screenshots_enabled` before the platform keeps any image.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Screenshots come from an optional `screenshot` tool in a separate sensor image, off by default (owner decision, research/106 §10.1) | Keeps the default sensor image small and free of a browser |
| D2 | Captures travel in the existing results report: the reserved asset property `web_evidence` | No new sensor endpoint or artifact store; segmented, signed, size-limited upload already exists |
| D3 | The platform keeps screenshots only when the organization turned them on | A screenshot shows whatever the page shows (personal data, internal dashboards) |
| D4 | Every image is decoded and re-encoded to PNG within 1 MiB and 1920x2400 px | Only pixels survive: no metadata, no polyglot payload, no SVG |
| D5 | Screenshots are served by their own data-scoped route, never by `/api/v1/attachments` | The attachment routes check pentest permissions, not the asset's data scope |
| D6 | The snippet is masked with the finding-evidence masker and the values are not kept | Responses often echo tokens and cookies |

Not built: per-finding screenshots (findings already accept `screenshot`
evidence references), a full response body store, video/HAR capture,
screenshots of third-party (unconfirmed) assets.

## 3. Contract (sensor → platform)

A report asset (any type; usually `website`, `service` or `subdomain`) may
carry:

```json
"properties": {
  "web_evidence": [{
    "url": "https://app.example.com/",
    "final_url": "https://app.example.com/login",
    "status_code": 200,
    "title": "Sign in",
    "server": "nginx",
    "content_type": "text/html; charset=utf-8",
    "snippet": "<!doctype html>...",
    "snippet_truncated": true,
    "captured_at": "2026-10-11T08:00:00Z",
    "screenshot": {"media_type": "image/png", "data": "<base64>"}
  }]
}
```

Platform limits (whatever the sensor claims): 5 captures per asset, 50 per
report, 20 screenshots per report; URLs absolute http(s), credentials
stripped, at most 2 KiB; title 300 B, server 200 B, snippet 4 KiB (cut on a
rune boundary, masked); `captured_at` within the last 30 days, never in the
future (else the ingest time); screenshot PNG or JPEG, at most 1 MiB decoded
and 1920x2400 px, re-encoded to PNG. An invalid capture is skipped and
counted, never fatal. Captures attach only to assets the report may change
(RFC-040 §5.3 binding) and never to the asset's properties.

### 3.1 Sensor tool (sensor repository)

`screenshot` is a tool in the optional `evidence` sensor image:

- headless Chromium driven per target with a fresh profile, no extensions,
  no persistent storage, downloads and file chooser disabled, permissions
  (camera, geolocation, notifications, clipboard) denied;
- JavaScript runs (pages need it to render) but the browser's network is
  limited to the target's origin and its redirects inside the job's scope;
  requests to any other origin, to private ranges not in scope and to the
  sensor's own platform endpoint are blocked by the sensor's egress policy
  (local policy and the outbound guard), so a page cannot exfiltrate through
  the sensor;
- a fixed viewport (1280x800), a 15 s page budget, one page at a time per
  job, output capped before upload;
- runs inside the per-task sandbox (unprivileged user, private workdir,
  rlimits, seccomp, no access to the sensor key, outbox or config) and only
  when the sensor's local policy enables the `screenshot` capability;
- only for targets the job carries (typed, in scope, active-allowed assets):
  the platform's active-probe gate already applies.

## 4. Platform design

- Table `asset_web_evidence` (tenant, asset, fields above, screenshot key,
  provider, sha256, size, dimensions, `screenshot_expires_at`), FK to the
  asset with cascade. A trigger queues the file of every deleted row in
  `asset_web_evidence_orphans`, so no stored image outlives its row.
- Ingest step 10 resolves each report asset to the stored asset and calls
  `webevidence.Service.RecordReport` once per report (one settings read).
- Files go through the attachment storage resolution (operator storage or the
  organization's own bucket, `{tenant}/` namespace), without an attachment
  row; organization deletion erases the namespace as for attachments.
- `web-evidence-retention` controller (hourly): detach and delete expired
  screenshots, delete queued orphan files, delete capture text older than a
  year.
- Routes (module `attack_surface`, `assets:read`, the asset must be in the
  caller's data scope, else 404):
  - `GET /api/v1/assets/{id}/web-evidence` — newest 5 captures;
    `Cache-Control: no-store`;
  - `GET /api/v1/assets/{id}/web-evidence/{evidence_id}/screenshot` — the PNG
    with `Content-Security-Policy: default-src 'none'; sandbox`,
    `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy:
    same-origin`, `Cache-Control: private, no-store`; the stored bytes are
    served only when their length matches the record.
- Setting `web_screenshots_enabled` on `/api/v1/easm/settings` (off by
  default, audited with the section).
- Web: a **Web evidence** card on the asset page (text only, the screenshot
  as an image from the route above) and a **Screenshots of web assets**
  switch on the monitoring card (en, vi).

## 5. Threat model

| Asset / actor | Abuse case | Control |
|---|---|---|
| Another organization | Read captures or screenshots | Every query has the tenant; the asset is resolved in the token's tenant and the caller's data scope; DB and handler tests |
| Member outside the asset's data scope | Fetch a screenshot by guessing ids | Asset scope check first (404); the capture is looked up by tenant, asset and id together |
| Hostile sensor or report | Store a polyglot, SVG or oversized image; XSS through the title or snippet | Magic-byte check, dimension and size caps, decode and re-encode to PNG; text fields capped and rendered as React text; the image route is sandboxed and nosniff |
| Hostile sensor | Attach evidence to an asset it may not change | Ingest uses only assets the report may change (RFC-040 binding) |
| Target page | Exfiltrate through the sensor's browser; read local files | Separate optional image; sandboxed task; egress limited to the target's in-scope origin; no file access; fixed time and size budget |
| Secrets in responses | Leak through the snippet | Masked at ingest; values not kept |
| Privacy | Screenshots of personal data kept forever | Off by default; 30-day retention; orphan queue; tenant erase |
| Storage exhaustion | Many large images | 1 MiB per image, 20 per report, 5 captures per asset, 30-day retention |

## 6. Rollout

Migration `asset_web_evidence` (two new tables, a trigger). Nothing changes
until a sensor sends captures; screenshots also need the organization's
switch. The sensor tool follows in the sensor repository.

## 7. Tests

`pkg/domain/webevidence` (credentials stripped, javascript: refused, control
characters, snippet masking and cut, polyglot trailer removed by the
re-encode, SVG/GIF/oversized/truncated images refused, switch off drops
images); `postgres.TestAssetWebEvidenceRepository` (newest 5 kept, dropped
and cascaded screenshots queued once, cross-tenant get, expiry);
`webevidence` service (switch, fail-closed settings, storage failure keeps the
text, failed insert deletes the file, tampered file refused, sweep);
`ingest.TestRecordWebEvidence` (only assets the report may change; the
property never stored); handler tests (out-of-scope 404, sandbox headers);
web tests (text rendering, image route, hidden without captures or module).
