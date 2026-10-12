# RFC-027: Betterleaks replaces gitleaks as the secret scanner

| | |
|---|---|
| Status | Accepted, implemented |
| Repos | sdk-go, sensor, api (migration 000241), ui, helm-charts, docs |
| Upgrade notes | [docs: Upgrading gitleaks → Betterleaks](https://github.com/openctemio/docs/blob/2d04e895f4233d502fa63976f8b9f32971c64147/operations/upgrade-gitleaks-to-betterleaks.md) |
| Architecture | [secret-scanning.md](../architecture/secret-scanning.md) |

## 1. Decision

The secret scanner is [Betterleaks](https://github.com/betterleaks/betterleaks)
**v1.9.0**, replacing gitleaks 8.30.0. Betterleaks is maintained by the
people who made gitleaks, including its original author; MIT licence.

The platform keeps **one** secret-scanner identity, `betterleaks`. Existing
configuration and findings are migrated to it; reports from sensors released
before the switch are mapped to it at ingest.

## 2. What was verified about Betterleaks

Checked against the v1.9.0 release (README, `--help`, release assets) and by
running v1.9.0 next to gitleaks 8.30.0 (the binary in the
`sensor:v0.3.0-default` image) on the same planted-secret repository:

| Claim | Verdict |
|---|---|
| Drop-in CLI | **v1: yes.** `dir`/`git`/`stdin` with the same flags, and `detect`/`protect` still run. Neither tool's `dir` has `--exclude-path` or `--no-git`; the SDK passed both, so exclusions had always failed (fixed). **v2.0.0-rc.1: no.** `-v` means validate, and SARIF/CSV/JUnit are dropped. |
| Backwards-compatible config | **Yes.** It reads `.gitleaks.toml`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML` and `gitleaks:allow`. v2 drops the `GITLEAKS_*` aliases. |
| JSON report field-compatible | **v1: yes.** Same fields (`RuleID`, `Description`, `File`, `StartLine`…`EndColumn`, `Match`, `Secret`, `Commit`, `Author`, `Email`, `Date`, `Message`, `Tags`, `Fingerprint`, `Entropy`, `SymlinkFile`) plus `Attributes` (`confidence`, `path`, `resource`). `Fingerprint` is built identically (`file:rule:line`). **v2:** an envelope (`schema_version`, `findings`, `scan`); the parser refuses it with `ErrV2Report`. |
| BPE-token detection | Yes ("Token Efficiency filtering"), alongside entropy. |
| CEL validation | Now **Expr**; CEL-shaped configs are still accepted. Validation is opt-in (`--validation`) and the sensor does not enable it: it would send discovered credentials to provider APIs. |
| Recursive decoding | Yes: `--max-decode-depth`, default 5 (gitleaks 8.30 has the same default). |
| Archive scanning | Yes: `--max-archive-depth`, **default 8** (gitleaks: 0, off). |
| Exit codes | 0 when clean or with `--exit-code 0`, 1 when leaks are found. Same as gitleaks. |
| SARIF | v1 has it (driver name `betterleaks`). |

**Release assets:** `betterleaks_<v>_<linux|darwin>_<x64|arm64>.tar.gz`,
`betterleaks_<v>_windows_<x64|arm64>.zip`, `checksums.txt` (SHA-256) and
`checksums.txt.sigstore.json` (Sigstore bundle for `checksums.txt`). The
sensor images pin the linux archive SHA-256 per architecture:
- amd64 `f8b185a39ffcece2a1ca82bf3a4e7435cd81963ffd16b7a9128daf75f35f6de7`
- arm64 `1d39116e0a58dc94574715e2aa12a2dbd5062f193eee3fec011fef6ba06bd13b`

The CI jobs pin the amd64 SHA-256 the same way.

**Rule-set differences seen:** for an AWS key pair, gitleaks reports
`aws-access-token` (the key ID) and `generic-api-key` (the secret key).
Betterleaks reports only `aws-access-token`, with the secret key as a
required component (`aws-secret-access-key`); a key ID alone is not reported.
Betterleaks also finds secrets inside archives (`bundle.zip!deploy.env`).

## 3. Identity and data

- **Fingerprint.** The ingest fingerprint is
  `sha256(asset_id + ":" + base)`. `base` is the finding's own fingerprint
  when it is valid hex; otherwise it is the CTIS `secret:` fingerprint of
  path, rule, line and masked value. The tool name is not part of it.
  Betterleaks v1 reports the same rule ID, path, line and secret as gitleaks,
  and the SDK masks the secret the same way, so a secret both tools report
  keeps its fingerprint and its finding.
- **Tool name.** Auto-resolve (`findings.tool_name = $tool`), suppression
  rules and the sensor tool checks match the tool name exactly, and the
  upsert never rewrites `tool_name`. Left as `gitleaks`, existing findings
  would never be auto-resolved by a betterleaks scan, and a stale one would
  stay open forever. **Migration 000241 renames them.**
- **One mapping point per side.** API: `pkg/domain/tool.CanonicalName`
  (`gitleaks` → `betterleaks`) is applied where a name enters:
  - `ingest.Service.Ingest`, which every ingest path funnels into;
  - the protocol-v2 receiver, before its checks and header digest;
  - `tool.SameTool` for the report-vs-sensor-tools comparisons;
  - suppression rules on write;
  - the raw-upload adapter lookup (`scanner_type=gitleaks`).

  SDK: `core.CanonicalScannerName`, used by the command executor, the
  template validator and cache, and the sensor's scanner factory. No other
  code knows the old name.
- **Migration 000241** (add-only, idempotent; down provided):
  - Adds the `betterleaks` tool (fixed ID `…0111`) and copies its
    capabilities. Deactivates `gitleaks`, which stays for history.
  - Moves tenant tool configs and rule sources/rules/overrides/bundles to the
    new tool.
  - Renames the scanner name in `scans`, `scan_profiles.tools_config` keys,
    `scan_schedules.scanner_configs` keys, `pipeline_steps`, `sensors.tools`,
    workflow trigger `tool_filter`, `suppression_rules`, `scanner_templates`
    and `template_sources` (the CHECKs gain `betterleaks` and keep
    `gitleaks` for old pods during a rolling deploy).
  - Renames `findings.tool_name` and moves `tool_id`.
  - History is untouched (`scan_sessions`, `ingest_reports`,
    `tool_executions`, `assets.discovery_tool`).
- **API contract change** (ships with the UI): template type `betterleaks`,
  quota fields `betterleaks_templates` / `max_templates_betterleaks`.

## 4. Verification (scratch API on :18600, DB `betterleaks_test`)

1. API at migration 239 (develop build). The published
   `sensor:v0.3.0-default` image scanned a repository with three planted
   secrets plus one inside a zip, and pushed: 3 findings `gitleaks` (`aws-access-token`,
   `generic-api-key`, `github-pat`). Created a `gitleaks` scan, suppression
   rule and scanner template; sensor tools `{gitleaks}`.
2. Migration 000241 and the new API. Findings, scan, rule, template, sensor
   tools and the three system scan profiles all say `betterleaks`;
   `gitleaks` tool inactive, `betterleaks` active. Same finding IDs and
   fingerprints.
3. New sensor (betterleaks 1.9.0), full-coverage default-branch report:
   - `findings_created: 1` (the zip secret), `findings_updated: 2` (same IDs
     as the gitleaks findings);
   - `generic-api-key` auto-resolved (rule-set difference, §2).
4. The PAT was removed from the repository and re-scanned. The finding
   **gitleaks created in step 1** was auto-resolved by the betterleaks scan.
5. The v0.3.0 sensor pushed again (`tool: gitleaks`): accepted, stored as
   `betterleaks`, no new rows. Its rule-set difference reopened
   `generic-api-key` (the reason to upgrade all sensors at once).
6. The migrated `secrets-nightly` scan was triggered. The command was
   dispatched as `scanner: betterleaks` to a new-sensor daemon, ran, and
   updated the 2 existing findings. 4 finding rows in total after six runs.

## 5. Not done here

- **One-shot reports never auto-resolve.** No sensor path sets the CTIS
  `metadata.id` on a v1 report, so the server logs
  `auto-resolve skipped: report metadata.id is empty`. This predates the
  switch; protocol v2 (RFC-026) carries a report ID. The verification above
  set the ID on the sensor-produced report to exercise auto-resolve.
- Betterleaks v2 (envelope report, credential analysis) when it is released.
