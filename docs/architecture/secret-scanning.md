# Secret scanning

How a secret goes from a repository to a finding, and where the scanner's
name is decided. Decision record: [RFC-027](../rfcs/RFC-027-betterleaks-replaces-gitleaks.md).

```
repository ──► sensor: betterleaks dir <repo> --report-format json
                 │      (sdk-go pkg/scanners/betterleaks; v1.x only)
                 ▼
               parser: report → CTIS, tool.name = "betterleaks",
                 │      path made repo-relative, secret masked,
                 │      fingerprint "file:rule:line"
                 ▼
API ingest ──► tool.CanonicalName(report.tool.name)   ◄── old sensors say "gitleaks"
                 │
                 ▼
               finding fingerprint = sha256(asset_id ":" secret:path:rule:line:masked)
               upsert ON (tenant_id, fingerprint)  — tool_name kept from first writer
                 │
                 ▼
               full scan on the default branch:
               auto-resolve WHERE tool_name = 'betterleaks' AND scan_id <> this scan
```

## The scanner's name

There is one name, `betterleaks`, in the API's data and in every comparison.
Each side has exactly one place that knows the retired name `gitleaks`:

| Side | Function | Applied at |
|---|---|---|
| API | `pkg/domain/tool.CanonicalName`, `tool.SameTool` | `ingest.Service.Ingest` (all ingest paths), the v2 receiver (before the header digest), sensor-tool checks (`SensorDeclaresTool`, `sensorMayAutoResolveTool`), `suppression.Rule.SetToolName`, the raw-upload adapter registry |
| Sensor / SDK | `core.CanonicalScannerName` | command executor, custom-template validation and cache, the sensor's scanner factory, router and workspace confinement |

Stored configuration was migrated once (migration 000241). Nothing else
special-cases `gitleaks`.

## Why the tool name was migrated on findings

The finding fingerprint does not include the tool, but auto-resolve and
suppression match `tool_name` exactly, and an upsert never rewrites it.
Findings left as `gitleaks` would be updated by betterleaks scans and never
auto-resolved by them. Migration 000241 renames them, so they behave exactly
like findings betterleaks created.

## Report format

The parser reads the gitleaks/betterleaks v1 JSON array. A betterleaks v2
envelope (`{"schema_version": …}`) is refused with `ErrV2Report`. It is not
read as an empty report, because that would auto-resolve every secret.
The tool always runs without `--verbose`, which would print raw secrets into
the sensor log. `--redact` is not used either: it also redacts the report,
which would change masked values and fingerprints.
