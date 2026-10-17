# Asset technologies

Design: [RFC-112](../rfcs/RFC-112-asset-technologies.md).

What a fingerprinting probe detected on an asset: web server, framework or CMS, language, JavaScript
library, CDN, hosting, WAF or security service, analytics, security header, other.

## Flow

1. A report states technologies either typed (`asset.technologies[]` with name, version, CPE,
   categories, confidence) or loose (`properties.technologies`, `"Name:version"` strings, as httpx
   sends them).
2. Set reconciliation (RFC-069, `internal/app/ingest/attribute_sets.go`) records both forms as the
   source's observation of the `technologies` set and writes the resolved set to
   `assets.properties.technologies`.
3. `recordTechnologies` (`internal/app/ingest/technologies.go`) sanitises and classifies each detection
   (`pkg/domain/assettech`) and upserts the ones the asset now shows into `asset_technologies`.
4. When reconciliation writes a smaller set, `writeResolvedSet`
   (`internal/infra/postgres/asset_attribute_set_repository.go`) deletes the rows no longer shown, in
   the same transaction.
5. `recordSoftware` (`internal/app/ingest/software.go`) turns a technology into a software component
   only when `assettech.IsSoftwareCandidate` holds: software kind and a version or CPE.

## Categories and kinds

| Category | Kind |
|---|---|
| web_server, framework, language, js_library, other | software |
| cdn, hosting, waf | infrastructure |
| security_header | http_security |
| analytics | marketing |

`assettech.Classify`: curated name list, then the tool's categories, then `other`.

## Reading

`GET /api/v1/assets/{id}/technologies` (`assets:read`, tenant and data scope, 404 on a miss), ordered by
category and name, at most 500 rows.

## Limits

Name 128 bytes (no control characters, valid UTF-8), version 64 bytes, source 100 bytes, confidence
0-100. Per report: 100 technologies per asset, 5000 in all.
