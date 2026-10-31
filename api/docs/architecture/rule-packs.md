# Detection rules: web fingerprints and sensitive information

Design: [RFC-140](../rfcs/RFC-140-rule-packs.md). Code: `pkg/domain/contentrule` (rule format, validation,
engine), `internal/app/contentrule` (engines per organization, built-in packs, organization rules),
`internal/app/ingest/detection_rules.go` (ingest wiring).

## Rules

Two kinds, which are also content pack kinds ([content-packs.md](content-packs.md)):

| Kind | Finds | Becomes |
|---|---|---|
| `web-fingerprints` | a product and its version | an asset technology (and a software component when it has a version or CPE) |
| `secret-rules` | a credential, token, private key, internal host name, personal data or debug output | an exposure, masked |

A rules file (YAML, any `*.yaml` in a pack):

```yaml
schema: 1
rules:
  - id: nginx                      # a-z 0-9 . _ -, unique in the pack
    name: nginx
    technology: {name: nginx, category: web_server, cpe: "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"}
    confidence: 90                 # 1-100, default 70
    condition: any                 # any (default) or all of the matchers
    matchers:
      - location: header           # body, url, title, header, cookie, favicon, script
        header: server
        keywords: [nginx]
        pattern: '(?i)^nginx(?:/(?P<version>\d+(?:\.\d+){1,3}))?'
  - id: example-token
    name: Example token
    secret: {category: token, severity: high}   # credential, token, private_key, internal_host, pii, debug
    matchers:
      - location: body
        keywords: [tok_]
        pattern: '\b(?P<secret>tok_[A-Za-z0-9]{32})\b'
```

- Named groups: `version` (a fingerprint's version; `{version}` in the CPE, `*` when none) and `secret`
  (the secret value; the whole match when absent).
- Keywords are literals matched case-insensitively (ASCII). Body and script matchers need at least one; the
  pattern runs only within 256 bytes of a hit. Header, title, URL and cookie matchers may have a pattern
  alone. A favicon matcher lists hashes (signed 32-bit MurmurHash3, as the probe reports them).
- Secret rules read body, url, title, header or script, always have a pattern, and match on one matcher.

### Limits

| Limit | Value |
|---|---|
| pattern | RE2 syntax, 512 bytes, 4,000 compiled steps, 8 groups, repeat bound 256, must not match empty text |
| matchers per rule / keywords per matcher | 8 / 8 (3-64 characters each) |
| rules per pack / per organization | 2,000 / 200 |
| document read | body 1 MiB, script paths 64 KiB (200 paths), each other field 2 KiB, 32 headers, 20 cookies |
| per document | 2,000 pattern runs, 50 matches, 100 ms, 64 hits per keyword |

## Where rules run

At ingest, before anything is stored (`matchDetectionRules`). For each `http_service` asset of a report the
document holds: the URL, the final URL (`redirect_url`), the title, the `Server` header (`web_server`), the
cookie names of `http_posture`, the favicon hash and the paths of the report's endpoints on the same origin
that are scripts. Reports carry no other header value and no cookie value
([web-content-pipeline.md](web-content-pipeline.md)).

- Fingerprint matches are added to the asset's technologies in the report (unless the tool reported the
  same technology), so set reconciliation stores them; after the asset is stored their source
  (`rules:<pack>@<version>` or `rules:organization`), category, vendor, CPE and confidence are recorded.
- Secret matches are written, once the asset exists and only for assets the report may change, as
  exposures through the EASM exposure writer.
- A component that holds a raw web response calls `contentrule.Service.ScanDocument(tenant, asset,
  document)` before it normalizes or masks it.

Each organization's engine is the stable platform rule packs plus its enabled rules, compiled once and
reused for a minute; a change to its rules drops it at once. Parsed platform packs are cached by digest.

## Secrets

An exposure holds, in `details`: `url`, `rule_id`, `rule_scope`, `field`, `line`, `column`, `secret_kind`,
`secret_masked` (at most four characters at each end), `secret_length`, `secret_fingerprint` (HMAC-SHA256
under a per-tenant key derived from the server secret; empty without one) and, for a platform rule,
`pack`, `pack_version`, `pack_digest`. Its identity is the tenant, type, rule, asset, URL and fingerprint
(or the location without a key). Type `credential_leaked` for `credential`, `token`, `private_key`;
`sensitive_data_exposed` otherwise. The value is never stored, logged, audited or returned.

## Platform packs

The built-in packs `web-fingerprints-core` and `secret-rules-core` (`internal/app/contentrule/builtin`,
release `2026.10.1`) are written for this project. At start, each one whose name has no `stable` channel is
uploaded as a platform pack (lint, canonical form, platform signature) and `stable` points at it; an
existing channel is never moved. A newer release is imported or uploaded in the console like any platform
pack (`kind` `web-fingerprints` or `secret-rules`) and `stable` moved to it. Change `builtin.Release`
whenever a rule file changes.

## Organization rules

`/api/v1/content-rules` (tenant from the token; every query carries `tenant_id`):

| Route | Permission |
|---|---|
| `GET /` (the rules and the platform packs in use), `GET /{id}` | `scans:content:read` |
| `POST /`, `PATCH /{id}`, `DELETE /{id}` | `scans:content:write` |
| `POST /test` (a draft rule on a pasted sample of at most 256 KiB; masked result; nothing stored) | `scans:content:write` |

Stored in `tenant_content_rules` (one row per rule, unique `(tenant_id, kind, rule_id)`, `version` raised on
a content change, `sha256` of the canonical JSON). Audit: `content_rule.created|updated|deleted` with kind,
rule id and version. An organization cannot upload a rule pack.

## What a run used

A command-bound report adds `rules` to its command's `content_pins`: one entry per rule set (`kind`,
`scope` platform or organization, `pack`, `version`, `digest`, `rules`). The organization set's digest is
the sha256 of its rule ids, versions and hashes. The run's tasks return it with the wordlist pins.
