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

## Where the raw secret is masked

The raw secret must not reach any stored field, and the snippet is only one of them. A
scanner message, rule description or commit message can repeat it, and a
producer that masks only the snippet would leave it in the title. Masking
happens at three points, and each one is enough on its own:

1. **Converters** (`github.com/openctemio/ctis`, `RedactSecretFinding`): the
   SARIF converter and the gitleaks, betterleaks and trivy importers mask the
   secret, the match line and each secret-looking word of the match (8 or
   more characters with a letter and a digit, or 20 or more) in every plain
   string field of the finding. Nessus and Qualys mask the passwords, tokens
   and community strings that credential redaction found.
2. **Sensor runtime** (sdk-go `internal/toolrt`): every tool's output passes
   the output checks, and they apply the same rule to each finding.
3. **API ingest** (`internal/app/ingest/secret_redact.go`): `Ingest` and the
   result quarantine call `redactReportSecrets` before anything is stored,
   fingerprinted or logged.
   - A secret finding is one of type `secret`, or one whose tool is a secret scanner (the type `inferFindingType` gives it).
   - An unmasked snippet or `secret.masked_value` is taken for the raw secret and masked wherever any field repeats it.
   - A value that is already masked (asterisks, `REDACTED`) is kept, so a well-behaved producer's findings are stored unchanged and their identity does not move.

The masked form shows at most the first 4 characters of a secret of 16 or
more characters, and never more than a quarter of it. A shorter secret
becomes `REDACTED`. `processor_findings.go` then replaces the stored
snippet with the masked value (`redactSecretSnippet`).

`tests/integration/ingest_secret_redaction_test.go` ingests one applied
report and one quarantined report. It then checks that no column of any
tenant table holds the raw secret.
