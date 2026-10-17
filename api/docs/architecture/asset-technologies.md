# Asset technologies

Design: [RFC-112](../rfcs/RFC-112-asset-technologies.md).

What a fingerprinting probe detected on an asset: web server, framework or CMS, language, JavaScript
library, CDN, hosting, WAF or security service, analytics, security header, other.

## Flow

1. A report states technologies either typed (`asset.technologies[]` with name, version, CPE,
   categories, confidence) or loose (`properties.technologies`, `"Name:version"` strings, as httpx
   sends them).
2. Set reconciliation (RFC-069, `internal/app/ingest/attribute_sets.go`) records both forms as the
   source's observation of the `technologies` set. `writeResolvedSet`
   (`internal/infra/postgres/asset_attribute_set_repository.go`) collapses the resolved set to one
   element per name (`assettech.Collapse`) and writes it as `asset_technologies` rows in the same
   transaction: missing rows inserted (categorised by name), changed versions updated, rows no longer
   shown deleted.
3. `recordTechnologies` (`internal/app/ingest/technologies.go`) sanitizes and classifies each detection
   (`pkg/domain/assettech`) and enriches the existing rows (tool category, confidence, source, last
   seen). It never adds a row.
4. `assets.properties.technologies` (and the synonym `technology`) is retired: `Asset.SetProperty` /
   `SetProperties` drop it, and `tests/unit/retired_technologies_property_test.go` fails on any read in
   the API or the web console.
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

Asset responses embed `technologies` (name, version, category; 20 per asset on a list, all on one
asset), read with one query per page (`ListByAssets`).

`GET /api/v1/assets/{id}/technologies` (`assets:read`, tenant and data scope, 404 on a miss), ordered by
category and name, at most 500 rows.

## Limits

Name 128 bytes (no control characters, valid UTF-8), version 64 bytes, source 100 bytes, confidence
0-100. Per report: 100 technologies per asset, 5000 in all.
