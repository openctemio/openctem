# Finding evidence

> What a tool actually sent and received when it detected a finding, or
> re-checked it in a retest: the request, the response, where the check
> matched, what it extracted, and a command that reproduces it. Masked by
> default; secret values are revealed on demand, with a permission, a recent
> sign-in and an audit record. Design and decisions:
> [RFC-057](../rfcs/RFC-057-finding-evidence-and-retest.md).

## Model

One **item** is one piece of proof, tool-agnostic (the CTIS 1.6
`evidence_items[]` shape, `pkg/domain/evidence.Item`):

| Kind | Body |
|---|---|
| `http_exchange` | `http.request` (method, URL, version, headers, body, encoding, truncated, size) and `http.response` (status, reason, headers, body, truncated, size, time) |
| `raw_text` | `text`, `protocol` (dns, tls, ssh, banner, ...) |
| `command_output` | `command`, `exit_code`, `text` |
| `file_excerpt` | `file` (path, lines, snippet) |
| `screenshot` | `artifact` (media type, sha256, size, ref) |
| `curl` | `text` (a tool's own reproduction command) |
| any other `[a-z0-9_.-]{1,64}` | kept; its JSON becomes `text` and is shown as text, never refused |

Every item may carry `match[]` (request or response; status, header, url or a
body byte range; the matcher name), `extracted[]`, `label`, `captured_at`,
the tool's `content_sha256` and `sensitive[]` (spans the tool marked, by JSON
pointer and byte range).

A tool sends its proof as CTIS 1.6 `finding.evidence_items` (any tool, the
third-party tier included; the ctis importers fill them for nuclei, SARIF
`webRequest`/`webResponse`, HAR and ZAP files). An unknown kind is kept with
its fields as text. A tool that predates them sends finding properties
(`request`, `response`, `curl_command`, `extracted_results`,
`matcher_name`, the nuclei sensor before CTIS 1.6); ingest turns those into
an `http_exchange` (raw HTTP parsed, the URL made absolute from the
matched-at) and a `curl` item, and highlights the extracted values in the
response body. When a finding carries both, `evidence_items` wins.

nuclei masks `Authorization` and `Cookie` itself (`***`, no option turns it
off): those values never reach the platform and are shown as the tool's mask,
not as revealable placeholders. Everything else in the exchange (query and
body parameters, `Set-Cookie`, custom key headers) arrives and is masked and
kept for reveal by the platform.

## Pipeline (ingest, `internal/app/evidence`)

1. **Normalize** (`evidence.Normalize`): valid UTF-8, no NUL, single-line
   fields without control characters; caps per part (body 64 KiB, keeping
   the window around the first match when cut; text 64 KiB; headers 100 and
   32 KiB per message; 20 extracted values; whole item 256 KiB, the DB
   refuses more); match ranges outside the stored body are dropped.
2. **Hash**: `content_sha256` is the platform's sha256 over the normalized
   item before masking. The tool's own hash is kept in the item.
3. **Mask** (`evidence.Mask`), always, whatever the tool marked:
   - headers: `Authorization` / `Proxy-Authorization` (scheme kept), every
     `Cookie` and `Set-Cookie` value (names kept), `X-Api-Key` and the other
     key, token, session, auth, signature and credential headers;
   - URLs (request, `Location`, `Referer`, in text): userinfo password,
     token-like query parameters;
   - bodies and text: form fields and JSON keys with secret names,
     `name=value` assignments, `Bearer`/`Basic` credentials, and credential
     shapes (JWT, AWS keys, GitHub, GitLab, Slack, Google, Stripe keys,
     private-key blocks); a base64 body that is UTF-8 text is decoded first;
   - the tool's `sensitive[]` spans.
   Each value becomes `«secret:kind#n»` **everywhere** in the item (echoes in
   the response, the curl command, extracted values), the same value the same
   placeholder; body match ranges move to where the matched text sits after
   masking.
4. **Encrypt**: each value is AES-256-GCM encrypted with the platform key
   (`APP_ENCRYPTION_KEY`, re-keyed by `cmd/rekey`). The plaintext is bound to
   tenant, item and placeholder (`evidence:v1|tenant|item|placeholder|value`):
   a ciphertext copied to another row does not open.
5. **Store**: `finding_evidence` (masked item, migration 001223) and
   `finding_evidence_secrets` (ciphertexts, expiring). A detection item
   the finding already holds (same content hash) is not stored again.

A secret finding keeps no evidence (its evidence is the leaked value itself).

## Bounds and retention

| | |
|---|---|
| detection items per finding | newest 20 (a repeated item is not stored again) |
| retest-attempt items per finding | newest 20 |
| items per finding per report / per retest attempt | 20 / 5 |
| new items per tenant per 24 h | 20,000 (excess dropped, logged) |
| masked evidence | 365 days |
| encrypted secret values | `settings.evidence.secret_retention_days`, default 30 (1–365) |

The `finding-evidence-retention` controller (hourly) deletes expired secret
values (the item stays, no longer revealable) and items past 365 days.
Deleting a finding or a tenant deletes its evidence and secrets (foreign
keys); a finding merge moves the loser's evidence to the survivor.

Stored files (attachments and manual evidence files, under
`{tenant id}/` on the server storage, `STORAGE_LOCAL_PATH` or the
`STORAGE_PROVIDER=s3|minio` bucket, and in the organization's own bucket when
it set one) are deleted when the organization is deleted
(`DELETE /api/v1/tenants/{tenant}`): the whole `{tenant id}/` namespace on every
backend first, then the rows, then the namespace once more for an upload that
raced the delete. If a backend cannot be erased the deletion is refused (503,
audited as a failed `tenant.deleted` on the organization's own log) and nothing
else changes; the owner retries. An organization whose own bucket no longer
accepts its keys fixes the keys, or switches its storage setting back to the
server storage, before deleting.

## API

| Route | Gate |
|---|---|
| `GET /api/v1/findings/{id}/evidence-items[?retest_id=]` | `findings:read` + data scope; masked items, newest first (25), with `curl` built from the masked request, `revealable` placeholders and `secrets_available`; `Cache-Control: no-store` |
| `POST /api/v1/findings/{id}/evidence-items/{item_id}/reveal` `{placeholders[≤50], purpose: view\|copy\|copy_curl}` | `findings:evidence:reveal` + data scope + 30-per-user burst (one per 2 s) + step-up; `{values, mask_after_seconds: 60}`, `Cache-Control: no-store`; 410 once the values expired |
| `GET/PUT /api/v1/organization/settings/evidence` | owner/admin |

A reveal is audited **before** values are returned (`finding.evidence_revealed`:
item, kind, placeholder names, purpose; never values) and adds an
`evidence_revealed` entry to the finding's timeline. If the audit event cannot
be written the reveal answers 503. API keys cannot step up, so they can never
reveal. Nothing else reads these tables: finding lists, the finding detail,
exports, notifications, tickets, webhooks and AI-triage prompts never carry
evidence.

## Web

The finding's **Evidence** tab starts with **Tool evidence**: one card per
item with kind, tool, rule, template digest, content hash and time; for an
HTTP exchange, the request line, headers and body and the response status,
headers and body, in a parsed or raw view, the matched part highlighted with
`<mark>`. Everything is React text (`toDisplayBlock`: control and direction
characters shown as escapes), never HTML. Masked values are chips; **Reveal**
(permission-gated, step-up dialog on demand) shows a value inline and masks it
again after 60 seconds; copy and **Copy curl with secrets** go through the
same audited reveal. **Copy curl** and **Download** are masked.

## Threat model

| Threat | Control |
|---|---|
| Credentials of a scanned target leak through the UI, exports, notifications, tickets | masked at ingest; plaintext only encrypted in `finding_evidence_secrets`; read only by the reveal route |
| Cross-tenant or out-of-scope read or reveal | tenant-scoped queries; DataScopeGuard 404; the finding is checked in the tenant; ciphertext bound to tenant and item |
| A compromised session or API key exfiltrates secrets | permission + step-up (API keys refused) + per-user rate limit + audit before return + timeline entry + 30-day expiry |
| Hostile tool content (XSS, bidi tricks, huge bodies) | text-only rendering with escapes; caps at ingest; DB size check |
| Storage exhaustion | per-item, per-finding and per-tenant caps; dedup; retention |
| Key rotation | `finding_evidence_secrets.ciphertext` is a `cmd/rekey` location |

## Code

| Piece | Where |
|---|---|
| Item, caps, masking, raw HTTP parsing, curl | `pkg/domain/evidence` |
| Service (store, list, reveal, sweep) | `internal/app/evidence/service.go` |
| Ingest | `internal/app/ingest/evidence_items.go` (step 9 of the finding processor) |
| Repository | `internal/infra/postgres/finding_evidence_repository.go`, migration `001223_finding_evidence` |
| Routes / handler | `internal/infra/http/routes/finding_evidence_items.go`, `internal/infra/http/handler/finding_evidence_items_handler.go` |
| Retention | `internal/infra/controller/finding_evidence_retention.go` |
| Settings | `pkg/domain/tenant/evidence_settings.go` |
| Web | `web/src/features/findings/components/detail/finding-evidence-items.tsx`, `web/src/features/findings/lib/evidence-view.ts` |

## Tests

- `pkg/domain/evidence/evidence_test.go`: every secret masked everywhere
  (headers, cookies, URL query, form and JSON bodies, base64 text bodies,
  echoes, curl), names and schemes kept, tool-marked spans, caps and the
  match window, unknown kinds, curl quoting.
- `internal/infra/http/routes/finding_evidence_items_authz_db_test.go`
  (Postgres, least-privilege role): masked reads, no plaintext in any table,
  cross-tenant and out-of-scope 404, permission 403, step-up and API-key 403,
  one audit row and one timeline entry per reveal and none for a refusal,
  no-store, expiry 410, rate limit 429, retention sweep, finding and tenant
  erasure, ciphertext bound to its item, dedup and pruning.
- `web/.../__tests__/finding-evidence-items.test.tsx`: hostile HTML and
  scripts rendered as text, match highlighting, no Reveal without the
  permission or after expiry, reveal then re-mask after 60 s, masked curl by
  default and curl with secrets only through a reveal.
