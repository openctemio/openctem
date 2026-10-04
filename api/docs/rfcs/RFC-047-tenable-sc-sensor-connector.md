# RFC-047 — Tenable.sc two-way sensor connector

> Status: **Proposed** (2026-10-04). Owner decision D-14 (2026-10-04, final):
> rebuild the Tenable integration as a **two-way Tenable Security Center
> (Tenable.sc) connector that runs inside the sensor**. Pull assets,
> vulnerabilities and plugin metadata; push scan launches and schedules; keep
> the Tenable credentials on the sensor.
> Scope: sensor (`openctemio/sensor`: the connector, its config and its
> Tenable.sc client) + api (command types, integration, ingest, coverage) +
> web (integration page, once it works). sdk-go needs no change for P0 (§5.2).
> Replaces the runner design of
> [RFC-007](RFC-007-license-aware-scan-coverage.md) §3.9–§3.10 (Paused by
> #990); keeps RFC-007's coverage invariants and rebuilds its planner on this
> connector (§9).
> Builds on and does not repeat:
> [RFC-040](RFC-040-platform-sensor-mutual-distrust.md) (signed jobs, the
> sensor-local policy, result binding, quarantine, hostile results),
> [RFC-043](RFC-043-deduplication-and-identity.md) (network VA identity),
> [RFC-044](RFC-044-issue-definitions-and-findings.md) (Tenable plugins in the
> definition catalog), [RFC-046](RFC-046-scans-redesign.md) (Scan → Run → Task,
> schedules) and the [active-probe gate](../architecture/active-probe-gate.md).
> Rebuild ticket: #989.

## 1. Answer in short

- **Where it runs.** The connector is part of the sensor binary, next to the
  tool wrappers. The sensor is inside the customer network and is the only
  component that talks to Tenable.sc. The platform needs no route to
  Tenable.sc, and Tenable.sc needs no route to the platform.
- **Credentials.** The Tenable API keys (`accessKey`/`secretKey`, sent as the
  `x-apikey` header) live in a sensor-local config file or secret files. The
  platform never receives, stores or forwards them. It knows the Tenable.sc
  instance only by a name the sensor owner chose.
- **How the platform asks.** Two new declarative command types, pinned to the
  sensor the integration names:
  - `connector_sync`: read-only pull of hosts, cumulative and mitigated
    vulnerabilities, and plugin metadata;
  - `connector_scan`: create and launch one Tenable.sc scan on gated targets,
    wait for it, and pull its results.

  Both carry `scanner: "tenable_sc"`, so today's local-policy tool gate and the
  result-binding tool check apply with no SDK change.
- **What the sensor refuses.** Besides the RFC-040 local policy (kill switch,
  `checks.allow`, `tools.allow`, targets, ports), the connector config holds a
  second allow-list the platform cannot change: which operations, which
  Tenable repositories may be read, which scan policies, repositories and zones
  a launched scan may use, and how many targets a scan may have.
- **How results come back.** As CTIS reports pushed through the normal sensor
  ingest, bound to the command (RFC-040 §5.3). Pulled vulnerabilities map onto
  the RFC-043 network VA identity (asset, CVE or plugin, port/protocol), so a
  Tenable.sc pull, a `.nessus` import and a Tenable.sc scan of the same host
  converge on the same findings.
- **Resolve semantics.** A vulnerability Tenable.sc moved to its mitigated
  database resolves the matching open finding, behind an
  `off | dry_run | enforce` gate (default `dry_run`), never touching a finding
  a person triaged. A pull never closes anything by absence.
- **Phases.** P0 pull only (read path end to end). P1 scan launch and
  OpenCTEM-owned schedules. P2 license-aware coverage planner on top of P1. The
  integration page stays hidden (#990) until P0 works end to end.

## 2. Background

### 2.1 What exists and why it stopped

| Piece | Where | State |
|---|---|---|
| RFC-007 planner, scheduler, dispatcher, `tenable_config.go`, coverage stats | `api/internal/app/scancoverage/`, `internal/infra/controller/coverage_scheduler.go`, migration `000176_scan_coverage_state` | Kept, not registered since #990 (`tenableCoverageRunnerAvailable = false`). `ActiveIPs` returns 0 |
| Tenable provider | `pkg/domain/integration` (`ProviderTenable`) | `HasClient()` false since #990: create refused, stored rows load |
| `.nessus` parser and findings upload | `pkg/parsers/nessus` (#988), `POST /api/v1/assets/import/nessus-findings` | Works; runs with the uploader's rights after #985 (L-05) |
| Nessus Pro REST client and `.nessus` → CTIS | sdk-go `pkg/scanners/tenable` | Kept in sdk-go v0.17.0; no Tenable.sc client |
| Sensor Tenable runner | sensor `internal/executor/tenable.go` (sensor#25, target guard #26) | **Removed in sensor v0.8.0** (sensor#107) with the whole `-platform` mode. It was reachable only through the `/api/v1/platform/*` job protocol, which the API no longer serves. It was dead code, not a rejected design. It also only ever implemented Nessus Pro: Tenable.sc returned "not yet supported" |

The lesson the old runner teaches: a connector must sit on the path every
sensor actually runs (the daemon's command poller in `sdk-go/pkg/sensorkit`),
not on a side protocol, and the platform must not offer a feature whose
consumer is not deployed. §10 makes the platform check that the pinned sensor
advertises the connector before it creates a command.

### 2.2 Tenable.sc API facts this design depends on

Sources: the Tenable Security Center API reference
(docs.tenable.com/security-center/api) and the API Best Practices Guide
(revised 2026-07-17). Items marked *unverified* are not stated by those
documents and must be confirmed against a real instance (§12.4).

| Topic | Fact |
|---|---|
| Base path | `https://<host>/rest/<resource>` |
| Auth | API keys: header `x-apikey: accesskey=<A>; secretkey=<S>;`. Needs Tenable.sc **5.13 or later**, API key authentication enabled in system configuration, and keys generated for a user. Sending both a session token and API keys is a 400. The alternative (`POST /rest/token` with username and password, then `X-SecurityCenter` + session cookie) is **not supported** by this connector: it needs a password and server-side session state |
| Envelope | `{"type", "response", "error_code", "error_msg", "warnings", "timestamp"}`; `error_code` 0 on success. Many numbers arrive as JSON strings (`"totalRecords": "1234"`, `"port": "443"`, `"severity": {"id": "4"}`), so the decoder accepts both |
| Analysis | `POST /rest/analysis` with `type: "vuln"`, `sourceType` `cumulative` (open), `patched` (mitigated) or `individual` (one scan result, with `scanID` and `view`), and a `query` with `tool` (`vulndetails`, `listvuln`, `sumid`, `sumip`, …), `filters [{filterName, operator, value}]`, `startOffset`/`endOffset` (inclusive start, exclusive end). Response `{totalRecords, returnedRecords, startOffset, endOffset, results}` |
| Time filters | `lastSeen` (needs `cumulative`), `firstSeen`, `lastMitigated` (needs `patched`); value `"a:b"` = days ago, **day granularity** |
| vulndetails fields | `pluginID, severity, hasBeenMitigated, acceptRisk, recastRisk, ip, uuid, port, protocol, pluginName, firstSeen, lastSeen, exploitAvailable, synopsis, description, solution, riskFactor, vprScore, baseScore, cvssVector, cvssV3BaseScore, cvssV3Vector, cvssV4BaseScore, cve, bid, checkType, family, repository, hostUniqueness, vulnUniqueness, hostUUID, vulnUUID, acrScore, assetExposureScore, dnsName, macAddress, netbiosName, operatingSystem, recastRiskRuleComment, acceptRiskRuleComment, pluginInfo`; `pluginText`, `seeAlso`, `exploitFrameworks`, `patchPubDate`, `pluginPubDate`, `vulnPubDate`, `cpe`, `lastMitigated` as available (*unverified per version*) |
| Plugins | `GET /rest/plugin` with `filterField/op/value`, `startOffset/endOffset` (default 0–50), `sortField`, `type`, `fields`, `since` (epoch seconds); `GET /rest/plugin/{id}`. Fields include `family, type, cvssV3BaseScore, vprScore, vprContext, epssScore, exploitAvailable, exploitFrameworks, exploitEase, pluginPubDate, patchPubDate, modifiedTime, xrefs` |
| Hosts | `GET /rest/hosts`, `POST /rest/hosts/search` (`uuid, ipAddress, name, os, macAddress, firstSeen, lastSeen, netBios, acr, aes, source, repID`); newer releases only (*unverified minimum version*) |
| Asset lists | `GET /rest/asset` returns `usable` and `manageable` lists (admins: one list); types `static`, `dynamic`, `dnsname`, `combination`, `ldapquery`, `watchlist`, …; `ipCount`, `typeFields`, `repositories`. A static list is created with `definedIPs` |
| Repositories | `GET /rest/repository?type=Local&fields=id,name,dataFormat,vulnCount,typeFields` (`ipRange`, `trendingDays`) |
| Policies | `GET /rest/policy` returns `usable` and `manageable` (`id, uuid, name, description, status, policyTemplate`) |
| Scans | `POST /rest/scan` (`name, type: "policy", policy{id}, repository{id}, zone{id}, ipList, assets[{id}], schedule{type}, maxScanTime, timeoutAction, inactivityTimeout`); `POST /rest/scan/{id}/launch` returns `scanResult.id`; `GET /rest/scanResult/{id}` (`status`, `importStatus`, `running`, `totalChecks`, `completedChecks`, `finishTime`, `importFinish`); `POST /rest/scanResult/{id}/stop` |
| License | `GET /rest/status`: `licenseStatus`, `licensedIPs`, `activeIPs` |
| Limits | No documented request rate limit or maximum page size. The guide uses 50-record pages; the connector defaults to 1000 and caps everything itself (§8.4) |
| TLS | Installed with a self-signed certificate by default; customers often use an internal CA |

## 3. Goals and non-goals

**Goals**

1. Tenable.sc data (hosts, open and mitigated vulnerabilities, plugin
   metadata) arrives in OpenCTEM without the platform holding Tenable
   credentials or a route to Tenable.sc.
2. OpenCTEM can launch, and schedule, Tenable.sc scans on targets that pass the
   platform's active-probe gate **and** the sensor owner's local limits.
3. Findings from Tenable.sc dedup with `.nessus` imports and with each other
   (RFC-043), and keep the fields a prioritisation layer needs (§7.3).
4. Re-enable RFC-007 rolling coverage with real license numbers (P2).
5. Every failure is visible: a refused, failed or partial sync says why, and
   never moves the incremental cursor.

**Non-goals**

- Tenable Vulnerability Management (tenable.io) and Nessus Professional. The
  command and config shapes leave room for them (`scanner` names the engine),
  but this RFC builds Tenable.sc only.
- Writing back to Tenable.sc anything other than the scans OpenCTEM launches:
  no accept-risk or recast rules, no asset list edits, no repository deletes.
- A "direct" mode where the API calls Tenable.sc. RFC-007 kept it optional; this
  RFC drops it (§13).
- Moving IPs out of Tenable.sc repositories to reclaim licenses (§9.3).

## 4. Architecture

```
 platform (api)                                 customer network
 ─────────────────────────────                  ─────────────────────────────────────────────
 integration (provider tenable,                 sensor (daemon, sensorkit poller)
   engine tenable_sc, sensor_id,                  │ 1 claim command (pull, outbound only)
   instance "sc-prod", sync cfg)                  │ 2 [P1 RFC-040: verify signed envelope]
        │                                         │ 3 local policy: kill switch, checks.allow,
 sync controller / "Sync now"                     │   tools.allow (tenable_sc), targets, ports
 RFC-046 run (P1) / coverage (P2)                 │ 4 connector config: instance, operation,
        │ active-probe gate (scan only)           │   repositories, policies, zones, max targets
        ▼                                         ▼
 commands (connector_sync |  ── claim ──►   connector ── https + x-apikey ──► Tenable.sc /rest
   connector_scan), pinned                        │     (CA file / SPKI pin, caps, rate limit)
        ▲                                         │ 5 map to CTIS (hosts → assets,
        │                                         │   vulns → findings, plugins → finding fields)
 ingest (bound to command,  ◄── push CTIS ──      │ 6 push in chunks, bound to the command
   tool tenable_sc, quarantine                    │ 7 complete command with counts, license,
   policy, exclusions, RFC-043                    │   version, cursor hint (no credentials, no URL)
   identity, mitigated-resolve gate)
        │
 integration.last_sync_at / stats / sync_error; cursor advances only on success
```

Principles:

1. **The sensor owns the reach and the keys; the platform owns the intent.**
   The platform decides what to sync or scan and when. The sensor decides
   whether it will, against limits only its owner can change.
2. **Declarative commands only** (RFC-040 §5.8): no URL, path, header, query
   fragment or free-form filter crosses from the platform. The platform names
   an instance, an operation and typed parameters; the sensor builds every
   Tenable request itself.
3. **Results are hostile in both directions.** The sensor treats Tenable.sc
   responses as untrusted input (§8.4); the platform treats the sensor's CTIS
   as untrusted input (RFC-040 §5.4).
4. **Absence never resolves.** Only Tenable's explicit mitigated state, or a
   completed full-coverage scan of the same targets, closes a finding.

## 5. Commands

### 5.1 `connector_sync` (P0)

```json
{
  "scanner": "tenable_sc",
  "instance": "sc-prod",
  "integration_id": "8c0e…",
  "mode": "incremental",
  "window_days": 3,
  "include": ["hosts", "vulns", "mitigated", "plugins"],
  "min_severity": 1,
  "repositories": [5, 7]
}
```

- `mode`: `incremental` (filters `lastSeen` / `lastMitigated` on
  `0:window_days`) or `full` (no time filter on cumulative; mitigated limited to
  `0:full_mitigated_days`, default 30).
- `window_days`: computed by the platform from the last **successful** sync
  (§7.5), 1–365.
- `include`: subset of `hosts`, `vulns`, `mitigated`, `plugins`.
- `min_severity`: 0 (info) to 4 (critical), default 1: informational plugins
  are usually 70–90 % of rows and carry inventory facts, not vulnerabilities.
- `repositories`: optional narrowing; the sensor reads the intersection with
  its own allow-list, and refuses the job if the intersection is empty.
- No `targets`: a pull reads what the sensor owner allowed; it sends no packet
  to any host. The local-policy target check therefore has nothing to check;
  the repository allow-list is the read boundary (§8.2).

### 5.2 `connector_scan` (P1)

```json
{
  "scanner": "tenable_sc",
  "instance": "sc-prod",
  "integration_id": "8c0e…",
  "targets": ["10.20.0.0/28", "10.20.4.17"],
  "policy_id": 1000003,
  "repository_id": 5,
  "zone_id": 2,
  "max_scan_seconds": 14400,
  "min_severity": 1
}
```

- `targets` went through the active-probe gate before the command existed, so
  the local policy then checks them again (`targets.allow/deny`) and the
  connector config caps their count.
- The sensor creates a scan named `openctem-<command id>` with `ipList` =
  targets and `schedule.type` on demand, launches it, polls `scanResult` until
  `status` is final and `importStatus` is finished, pulls
  `sourceType: individual, scanID: <result>, view: all`, pushes the report with
  `coverage_type: full` only if the scan completed and imported, otherwise
  `partial`, and deletes the scan **definition** it created (results stay). On
  cancel or timeout it stops the scan result it launched.
- The sensor never edits, launches or deletes a scan it did not create in the
  same command.

### 5.3 Why two command types and no SDK change

- Two types let the sensor owner allow pull and refuse launch with the existing
  `checks.allow` list, and let the platform authorize them separately
  (`integrations:manage` for a sync, `scans:write` + the probe gate for a
  launch).
- `scanner: "tenable_sc"` is already read by the local policy's tool gate
  (`policyJob.tool`), by result binding (`commandTool`) and by the command tool
  gate, so a policy with `tools.allow` that omits `tenable_sc` refuses both
  types, and a bound report must say `tool.name = "tenable_sc"`.
- The sensor registers both types with `kit.HandleCommand`, which adds them to
  the poller's allowed types; the handler pushes with
  `kit.Client().PushFindings(core.WithCommandID(ctx, cmd.ID), report)`.
- A third-party sensor can implement the same contract; when one exists, the
  payload types move to sdk-go `core` (not needed for P0).

## 6. Sensor side

### 6.1 Connector config (sensor-local, owner-written)

```yaml
# /etc/openctem/connectors/tenable-sc.yaml  (root-owned 0640, mounted read-only)
apiVersion: openctem.io/connector-tenable-sc/v1
instances:
  - name: sc-prod                      # the only thing the platform knows
    url: https://sc.corp.example        # https only
    ca_file: /etc/openctem/tenable-ca.pem          # optional; system roots otherwise
    pin_spki_sha256: ["kV2x…="]                     # optional; checked in addition to the chain
    access_key_file: /run/secrets/tenable_sc_access_key
    secret_key_file: /run/secrets/tenable_sc_secret_key
    allow:
      operations: [sync]               # add "scan" to allow connector_scan
      repositories: [5, 7]             # required: nothing is read without it
      scan_policies: [1000003]         # required for scan
      scan_repositories: [5]           # required for scan
      scan_zones: [2]                  # optional; empty = Tenable's default zone only
      max_targets_per_scan: 512
      max_scan_seconds: 28800
    limits:
      page_size: 1000                  # 50..5000
      max_records: 1000000             # per sync, all kinds
      max_response_bytes: 67108864     # per HTTP response
      requests_per_second: 5
```

Rules (same posture as the RFC-040 policy loader):

- **Fail closed on load**: unknown keys, a duplicate instance name, a
  non-`https` URL, a missing key file, a world-writable config or key file, an
  empty `repositories` list, or `operations` containing `scan` without scan
  allow-lists all stop the sensor with a message. A missing config file means
  the connector is off and the capability is not advertised.
- **No skip-verify switch exists.** TLS uses the system roots, or `ca_file`
  instead of them, plus optional SPKI pins. Hostname verification is always on.
- Environment shorthand for single-instance installs:
  `TENABLE_SC_URL`, `TENABLE_SC_ACCESS_KEY_FILE`, `TENABLE_SC_SECRET_KEY_FILE`,
  `TENABLE_SC_CA_FILE`, `TENABLE_SC_REPOSITORIES`, `TENABLE_SC_OPERATIONS`
  (instance name `default`). Raw `TENABLE_SC_ACCESS_KEY` /
  `TENABLE_SC_SECRET_KEY` are accepted with a startup warning (environment
  values leak into process listings and crash dumps more easily than files).
- Keys are read once at start (and on SIGHUP), held in memory, sent only in
  the `x-apikey` header to the configured host, and never logged, pushed,
  written to the outbox or included in a command result.
- Credentials by reference (RFC-040 §5.9, Vault/CyberArk) replace the key
  files when that provider ships; the config grows `access_key_ref` then.

### 6.2 Tenable.sc client

- Base URL from config only; paths are constants of the client.
- `http.Client` with: TLS as above, `CheckRedirect` that refuses any redirect
  (a redirect could carry the key header to another host), dial through the
  RFC-040 guarded dialer with the built-in deny list (loopback, link-local,
  metadata, multicast); private ranges allowed (the appliance is internal).
- Per-request timeout (default 120 s for analysis pages, 30 s otherwise), a
  token-bucket rate limit, and retries with full-jitter backoff only for
  network errors, 429, 502, 503 and 504 (honouring `Retry-After`, capped at
  60 s, at most 5 attempts). **401 and 403 never retry**: the sync fails with
  `credentials_rejected` or `forbidden`, and the message names the instance,
  not the key.
- Response handling: read through `io.LimitReader(max_response_bytes + 1)`;
  over the cap fails the sync (`response_too_large`), never truncates; decode
  the envelope; `error_code != 0` is an error with the Tenable message capped at
  512 bytes; numbers accepted as JSON numbers or strings; unknown fields
  ignored; a page with more results than requested, or a `totalRecords` above
  `max_records`, fails the sync (`too_many_records`) before anything from that
  query is pushed.
- Version check at the start of each command: `GET /rest/system` (version) and
  `GET /rest/status` (license). Below 5.13 the command fails with
  `unsupported_version`.

### 6.3 Sync algorithm

1. Admission (poller): kill switch, `checks.allow` has `connector_sync`,
   `tools.allow` has `tenable_sc`.
2. Connector admission: instance exists; `sync` in `operations`; requested
   repositories ∩ allowed repositories is non-empty.
3. Plugins first (when included): collect the plugin ids the vulnerability
   pages reference and fetch their metadata in batches with
   `GET /rest/plugin?filterField=id&op=eq&value=<id>` (or `since` the last
   plugin sync for a full refresh), cached in memory for the command.
4. Cumulative vulnerabilities: `vulndetails`, `sourceType: cumulative`,
   filters `repository` (allowed ids), `severity` (≥ `min_severity`),
   `lastSeen 0:N` in incremental mode, sorted by a stable key, paged by
   `page_size`.
5. Mitigated vulnerabilities: the same with `sourceType: patched` and
   `lastMitigated 0:N`.
6. Hosts come out of the vulnerability rows (every host with at least one row at
   or above `min_severity`, and every host with an informational row when
   `min_severity` is 0). `/rest/hosts` is used where the version has it, to
   add hosts without findings.
7. Map (§7) and push in chunks of at most 2000 findings per CTIS report, each
   bound to the command, with the report's `coverage_type` `incremental`.
8. Complete the command with metadata: counts per kind (`hosts`, `open`,
   `mitigated`, `plugins`, `skipped` by reason), pages, `truncated: false`,
   Tenable version, `licensedIPs`/`activeIPs`, the repositories actually read,
   the newest `lastSeen` and `lastMitigated` seen, and duration. Nothing else.

A failure after some chunks were pushed fails the command; the pushed findings
stay (they are true observations), the cursor does not move, and the next sync
re-reads the window. Ingest is idempotent per identity, so re-reading is safe.

### 6.4 Scan algorithm (P1)

As §5.2, with these extra checks before the first Tenable call: `scan` in
`operations`; `policy_id` in `scan_policies`; `repository_id` in
`scan_repositories`; `zone_id` empty or in `scan_zones`; `len(targets)`
≤ `max_targets_per_scan` (counting CIDR sizes, as RFC-007's `CountIPs`);
`max_scan_seconds` ≤ the config cap; every target inside the local policy
(already checked by admission) and, as a last line, every target re-checked by
the guarded resolver. The scan's `ipList` is built from the checked targets
only, joined with commas, never from free text.

## 7. Data mapping

### 7.1 Hosts → assets

Same rules as `pkg/parsers/nessus` and sdk-go `tenable.Convert`, so the three
Tenable paths land on the same asset:

| Tenable | CTIS asset |
|---|---|
| `dnsName` (FQDN) else `ip` | `value`; type `host` for a name, `ip_address` for an address |
| `ip` | `properties.ip_address`; also the asset when there is no DNS name |
| `netbiosName` | `name` when there is no DNS name; `properties.netbios_name` |
| `macAddress` | `identifiers.mac_addresses` |
| `operatingSystem` | `technical.os` / `properties.os` |
| `hostUUID`, `uuid` | `properties.tenable_host_uuid` (not an RFC-028 strong identifier: it is per Tenable install) |
| `repository {id, name}` | `properties.tenable_repository_id`, `tenable_repository` |
| `acrScore`, `assetExposureScore` | `properties.tenable_acr`, `tenable_aes` (never written into OpenCTEM criticality) |

Overlapping address spaces: Tenable.sc separates two networks that reuse
10.0.0.5 by repository (`hostUniqueness`). OpenCTEM keys an IP asset per
tenant. P0 refuses to guess: when the same IP appears in two allowed
repositories with different host UUIDs in one sync, the sensor pushes both rows
with their repository and the platform logs a `tenable_ip_collision` warning;
the zone-keyed identity of RFC-042 (P1 "zone-keyed identity") is where this is
solved, by mapping a repository to a scan zone (owner question Q5).

### 7.2 Vulnerabilities → findings

| Tenable | CTIS finding |
|---|---|
| `pluginID` | `rule_id` = plugin id; `identifiers` `{type: rule, namespace: TENABLE, value}` (RFC-044) once ctis carries identifiers |
| `pluginName` | `title` |
| `severity.id` 0–4 | `info`, `low`, `medium`, `high`, `critical` |
| `cve` (comma-separated) | `vulnerability.cve_ids` (all), `vulnerability.cve_id` (first) |
| `cvssV3BaseScore`/`Vector`, `cvssV4BaseScore`, `baseScore`/`cvssVector` | `vulnerability.cvss_*` (v3 preferred, as the Nessus parser) |
| `vprScore` | `vulnerability.vpr_score` |
| `exploitAvailable`, `exploitFrameworks`, `exploitEase` | `vulnerability.exploit_available`, `properties.tenable_exploit_frameworks`, `tenable_exploit_ease` |
| `epssScore` (plugin) | `vulnerability.epss_score` |
| `cpe` | `vulnerability.cpe` |
| `synopsis`, `description` | `description` (synopsis first), capped |
| `solution` | `remediation.recommendation` |
| `seeAlso`, `xrefs` | `references` (http/https only) |
| `pluginText` | `evidence`, capped at 64 KiB |
| `port`, `protocol` | `network {host, port, protocol}`; port 0 = host-level |
| `firstSeen`, `lastSeen` | `first_seen_at`, `last_seen_at` |
| `family`, `checkType`, plugin `type` | `properties.tenable_plugin_family`, `tenable_check_type`, `tenable_plugin_type` |
| `pluginPubDate`, `patchPubDate`, `vulnPubDate`, `pluginModDate` | `properties.tenable_*_date` (RFC 3339) |
| `acceptRisk`, `recastRisk` (+ rule comments, capped) | `properties.tenable_accept_risk`, `tenable_recast_risk`, `tenable_recast_severity` |
| `hasBeenMitigated`, `lastMitigated` | `properties.tenable_previously_mitigated`, `tenable_last_mitigated` |
| `sourceType` | `properties.tenable_state` = `open` or `mitigated`; mitigated rows also set `status: resolved` |
| `repository`, `vulnUUID` | `properties.tenable_repository_id`, `tenable_vuln_uuid` |
| — | `fingerprint` = `tenable_sc:<repository>:<ip>:<plugin>:<port>/<proto>`. Never the identity: today ingest ignores a non-hex sensor fingerprint (`isValidFingerprint`), and RFC-043 item 12 keeps converter fingerprints as sighting keys |

### 7.3 Identity and dedup (RFC-043)

The platform computes the identity with the v2 network VA recipe, never from
the sensor's fingerprint: asset, canonical vulnerability id (one finding per
CVE for a multi-CVE plugin, decision D3), `port/proto` or `host`. A plugin
without a CVE keys on the plugin id + port/proto, which is the natural Tenable
key (plugin, port, protocol, host). The Tenable fingerprint is kept as the
sighting key, so the same Tenable row re-read by every sync is one sighting.

Accepted-risk and recast flags are **kept, not applied**: OpenCTEM's triage
stays a human decision in OpenCTEM. The Findings UI shows them as Tenable
facts. Mirroring them into OpenCTEM statuses is owner question Q3.

### 7.4 Plugins → catalog

Plugin metadata travels on each finding (§7.2) in P0. RFC-044 P3 imports it
into the definition catalog as `namespace: TENABLE` definitions with
`detects` relations to CVEs; plugins reported by a tenant's own Tenable.sc are
**tenant-scope** definitions (RFC-044 §5.4), never global content.

### 7.5 Incremental sync and the cursor

- The platform keeps the cursor on the integration (`last_sync_at` +
  `metadata.tenable.last_successful_sync`, `last_full_sync`). The sensor is
  stateless: a replaced sensor resumes from the platform's cursor.
- `window_days = ceil((now - last_successful_sync) / 24h) + 1` (one day of
  overlap, because Tenable filters by whole days), clamped to 1–365; no
  successful sync yet → `full`.
- A `full` sync runs every `full_sync_days` (default 7) to reconcile anything
  an incremental window missed.
- The cursor moves only when the command **completed** and every report it
  filed **completed** in ingest (the same "both halves" rule as
  `coverage_autoresolve.go`).

### 7.6 Resolve and reopen semantics

- **Mitigated → resolved.** A finding reported with `tenable_state:
  mitigated` resolves the matching OpenCTEM finding when all hold: the report
  is bound to a `connector_sync` or `connector_scan` command of tool
  `tenable_sc`; the finding is in an open state (`new`, `confirmed`,
  `in_progress`, `reopened`); it was last seen by `tenable_sc` (not only by
  another tool, so a Tenable mitigation never closes a nuclei sighting of the
  same CVE); and `lastMitigated` is newer than the finding's last sighting. A
  person's `false_positive`, `accepted` or `resolved` is never changed. A
  mitigated row that matches no finding creates nothing.
- Gate: `INGEST_SOURCE_RESOLVE=off|dry_run|enforce`, default `dry_run`, which
  logs, counts and writes a "would resolve" audit entry, as
  `INGEST_COVERAGE_AUTO_RESOLVE` does. Enforce is a tenant opt-in after the
  dry-run numbers are reviewed.
- **Reopen.** A cumulative row seen after a resolution reopens the finding by
  the existing rule (auto-reopen only from command-bound reports of the same
  tool, RFC-040 §5.3).
- **Absence.** `connector_sync` reports are `incremental` and their command
  type is not `scan`, so neither the report-level auto-resolve nor the
  coverage auto-resolve ever runs for them (tested). A P1 `connector_scan`
  report with `coverage_type: full` takes part in coverage auto-resolve for its
  targets only, exactly as RFC-007's batch invariant requires.

## 8. Security

### 8.1 Threat model

| # | Threat | Control |
|---|---|---|
| T1 | Platform compromise steals Tenable credentials | They are never on the platform (§6.1). The platform holds an instance name |
| T2 | Platform compromise uses the sensor to read Tenable data it should not | Repository allow-list in the sensor config; the platform can only narrow it |
| T3 | Platform compromise launches scans against arbitrary networks or with a destructive policy | `connector_scan` refused unless the owner listed `scan`; policies, repositories, zones and target count allow-listed; targets inside the RFC-040 local policy; signed jobs when RFC-040 P1 ships |
| T4 | Platform compromise turns the connector into an HTTP client for other hosts (SSRF) | No URL, path or header comes from the platform; redirects refused; guarded dialer; one configured host |
| T5 | Hostile or broken Tenable.sc response (huge body, deep JSON, malformed values, control characters, HTML in plugin text) | §8.4 caps on the sensor; RFC-040 §5.4 caps and sanitiser on the platform; text stored as text and encoded on output |
| T6 | Compromised sensor forges Tenable findings, or resolves real ones | Results bound to the command and tool; resolve only from mitigated rows of the same tool under the gate; tenant from the sensor's credential, never the report; quarantine for unsolicited reports (RFC-040 §5.3) |
| T7 | Cross-tenant leak | Integration, sensor and commands tenant-scoped; the sensor must belong to the integration's tenant; shared platform sensors are refused as connector sensors (they would hold one tenant's keys while serving others) |
| T8 | TLS interception between sensor and Tenable.sc | Verified TLS only; custom CA or SPKI pin; no skip-verify switch |
| T9 | Key leakage on the sensor host | Key files, not environment, recommended; never logged; least-privilege Tenable user (§8.3) |
| T10 | Platform overload by a large Tenable.sc estate | `max_records`, chunked reports, ingest quotas; info rows off by default |

### 8.2 Authorization and tenant isolation (platform)

| Action | Permission | Extra checks |
|---|---|---|
| Create, update or delete a Tenable.sc integration | `integrations:manage` | Sensor in the same tenant, active, advertises `tenable_sc`; no credentials in the config (RFC-007 §8 R3, already enforced) |
| Sync now | `integrations:manage` | One open `connector_sync` per integration (an open one is returned, as `refresh_content` does) |
| Scheduled sync | system controller | Claims due integrations per row (as #847) |
| Launch a Tenable scan (P1) | `scans:write` (and data scope over the targets, D9 #987) | Active-probe gate (exclusions, attribution, zone routing, private-range policy) |
| Read sync status | `integrations:read` | Tenant-scoped |

All repository queries are tenant-scoped; a cross-tenant sync, update or read
returns 404. Tests cover: another tenant's integration id, another tenant's
sensor as `sensor_id`, a platform sensor as `sensor_id`, a restricted member
launching a scan on out-of-scope targets.

### 8.3 Least privilege on the Tenable side (install guidance)

A dedicated Tenable.sc user for OpenCTEM with a custom role: for pull, view
only on the allowed repositories (and their asset lists); for scan, add
"create scans" with the allowed policies shared to it and no administrative
rights. Its API keys are generated for that user only. The install guide shows
the role.

### 8.4 Hostile Tenable.sc responses (sensor)

- Body cap per response (`max_response_bytes`), records cap per sync
  (`max_records`), page result count ≤ requested.
- Per-field caps before mapping: title 512 B, description and solution
  16 KiB, evidence 64 KiB, references 50 × 2 KiB, CVE list 200, comments 1 KiB.
- Strings: invalid UTF-8 replaced, NUL and C0/C1 controls (except tab and
  newline) dropped; references kept only for `http`/`https`.
- Numbers: scores clamped to their ranges (CVSS 0–10, VPR 0–10, EPSS 0–1,
  ACR 1–10, AES 0–1000); ports 0–65535; timestamps after 1990 and not more
  than one day in the future, otherwise dropped.
- Malformed JSON, a wrong envelope or an unexpected type fails the command;
  nothing from the failing query is pushed.

### 8.5 Audit

- Platform: `integration.sync_requested` (who, mode, window),
  `integration.sync_completed/failed` (counts, reason), the existing command
  audit for `connector_scan`, and "would resolve"/"resolved by source" entries
  per finding from the resolve gate.
- Sensor: every admitted or refused connector command in the local job log
  (RFC-040 §5.11), with instance, operation, repositories and counts, never
  keys.

## 9. Coverage (P2)

### 9.1 What carries over from RFC-007

The planner (`LicensePolicy.Headroom`, `SelectBatch`, `CountIPs`), the
`scan_coverage_state` cursor and the batch-scoped auto-resolve invariant stay.
The dispatcher no longer creates `scan` commands with `scanner: tenable`; a
batch becomes an RFC-046 run of a Scan whose engine is `tenable_sc`, and each
task is a `connector_scan` command, so coverage gets runs, partial outcomes,
deadlines and rollover from RFC-046.

### 9.2 License-aware batching

Every sync and scan reports `licensedIPs` and `activeIPs` from `/rest/status`.
The platform stores the latest values on the integration; `ActiveIPs()` stops
returning 0. Headroom = `licensedIPs - activeIPs - safety_margin`; a batch is
dispatched only when headroom covers it, and the next batch only after the
previous run's reports completed (RFC-007's "do not trust instant reclaim").

### 9.3 Reclaim

Tenable.sc frees licensed IPs when data leaves its repositories (aging, or an
administrator removing vulnerability data). P2 does **not** delete data from
Tenable.sc. The coverage UI shows the license numbers and that reclaim is the
Tenable administrator's aging setting. An optional, separately allow-listed
`reclaim` operation is owner question Q4.

## 10. Platform side

- `command.CommandTypeConnectorSync = "connector_sync"`,
  `CommandTypeConnectorScan = "connector_scan"`; both always pinned to a sensor
  (`SetSensorID`), TTL 6 h for sync, `max_scan_seconds` + 1 h for scan.
- Integration: provider `tenable`, config `engine: tenable_sc`,
  `execution_mode: sensor`, `sensor_id`, `instance`, `sync_interval_minutes`
  (existing column, default 360, minimum 60), `full_sync_days`,
  `min_severity`, `repositories` (optional narrowing). `HasClient()` returns
  true for Tenable again only for this engine and mode. Engines `nessus_pro`
  and execution mode `direct` stay refused.
- The sensor must advertise the tool `tenable_sc` in its manifest (RFC-033)
  with the operations its config allows (`connector_sync`, `connector_scan`
  capabilities), so the platform never queues a command no sensor will claim
  (the §2.1 lesson). Offline or non-advertising sensor → 409 with a reason.
- A sync controller (5 min tick) dispatches due integrations
  (`next_sync_at <= now`, no open sync), claiming each row once.
- Command completion updates `last_sync_at`, `sync_error`, `stats`
  (`hosts`, `open`, `mitigated`, `plugins`) and `metadata.tenable`
  (`version`, `licensed_ips`, `active_ips`, `last_successful_sync`,
  `last_full_sync`) when the command and its reports completed.
- Ingest: tool `tenable_sc` mapped to `FindingSourceVA` in `toolNameToSource`
  (today only `nessus` and `tenable` are); the mitigated resolve gate (§7.6);
  scope exclusions apply to new assets as for any report.
- No synthetic branch. The `.nessus` converter sets a fake default branch
  `{Name: "network"}` to pass the git-centric `ShouldAutoResolve` gate, but
  host findings get no `repository_branches` row, so
  `AutoResolveStaleByAssets` never matches them, and the branch makes
  coverage auto-resolve refuse the report (`coverageRepositoryScan`). Connector
  reports carry no branch; a `connector_scan` report relies on coverage
  auto-resolve (§7.6) instead.
- Command routing already works for the new types: `ClaimForSensor` only hands a
  command whose payload names a `scanner` to a sensor whose verified effective
  tools include it, so the sensor registers `tenable_sc` in its tool registry.
- No migration in P0 (the integration row already has `last_sync_at`,
  `next_sync_at`, `sync_interval_minutes`, `sync_error`, `stats`, `metadata`).
  P2 may add license columns if querying JSON proves too slow.

## 11. UI

The Tenable connector UI stays hidden (#990) until P0 runs end to end. Then:

- Settings → Integrations → Scanners: "Connect Tenable.sc" (pick a sensor that
  advertises the connector, type the instance name, sync interval, minimum
  severity); no credential fields at all, with a link to the sensor config
  snippet.
- Integration card: last sync time and outcome, counts, Tenable version,
  license use, "Sync now", and the refusal reason when the sensor refused
  (for example "repository 9 is not allowed by the sensor owner").
- Findings: Tenable facts (VPR, ACR, AES, plugin family, accept/recast flags,
  mitigated state) on the finding detail; no new list columns in P0.
- P1: Tenable.sc as an engine in the scan create dialog (policy and repository
  pickers fed by a `connector_sync` catalog pull of `/rest/policy`,
  `/rest/repository` and `/rest/asset`, filtered by the sensor's allow-lists).
- P2: the Coverage panel comes back with real license numbers.

## 12. Testing

1. **Fake Tenable.sc server** (sensor repo, `httptest`, TLS with a test CA):
   fixtures under `testdata/tenablesc/` crafted from the documented shapes
   (string and number variants, multi-CVE plugin, host-level port 0, IPv6,
   mitigated rows, accept/recast). Scenarios: pagination across pages and the
   exclusive `endOffset`; `error_code != 0` with HTTP 200 and with 403; 401;
   429 with `Retry-After` then success; 503 exhausting retries; a body over the
   cap; malformed JSON mid-page; `totalRecords` over `max_records`; a redirect
   to another host (refused, key never sent); a certificate from another CA
   (refused); a pin mismatch (refused).
2. **Mapping golden tests**: fixture → CTIS JSON golden file, reused by the API
   ingest test so both sides agree on the contract.
3. **Admission tests**: each local-policy and connector-config refusal
   (operation, repository, policy, zone, target count, kill switch).
4. **API**: integration validation (cross-tenant sensor, platform sensor,
   credentials in config, non-advertising sensor), sync endpoint authz,
   one-open-sync rule, cursor moves only on success, mitigated resolve in all
   three modes, never resolves triaged findings or other tools' findings,
   absence never resolves a sync report, `connector_scan` targets through the
   probe gate (P1).
5. **End to end**: scratch API + Postgres, a real sensor binary with the
   connector config pointing at the fake Tenable.sc, an integration and "Sync
   now": findings appear with the right identity, a second sync after a
   fixture moves a row to mitigated resolves it (enforce) or only audits it
   (dry run).
6. **Real instance** (before Accepted → Implemented): one run against a
   customer or trial Tenable.sc to confirm the *unverified* rows of §2.2.

## 13. Alternatives considered

| Alternative | Why not |
|---|---|
| API calls Tenable.sc directly ("direct" mode of RFC-007) | Puts Tenable credentials and a route into the customer network on the platform: exactly what RFC-040 forbids. Customers' Tenable.sc is internal anyway |
| Platform-held credentials sealed to the sensor (RFC-032 E10) | Possible later for tenants without file or vault access, but the platform would still hold them; the sensor config is simpler and stronger |
| Download `.nessus` exports from scan results and reuse the parser | Only covers scans, not the cumulative or mitigated databases; loses VPR/ACR/AES and accept/recast; large XML on the sensor |
| Reuse `collect` commands | `collect` has no typed payload, the SDK executor passes no options to collectors, and the platform never creates `collect` commands; a typed pair is clearer for policy and authz |
| One `connector` type with an `operation` field | The sensor owner could not allow pull and refuse launch with `checks.allow` |
| Tenable.sc-side schedules (iCal) created by OpenCTEM | Leaves long-lived objects in Tenable that OpenCTEM must reconcile, and keeps running if OpenCTEM is down or the owner revoked consent; OpenCTEM schedules (RFC-046) launch on demand instead (owner question Q2) |
| Absence-based auto-resolve for pulls | A pull window does not prove a vulnerability is gone; Tenable says so explicitly with its mitigated database |

## 14. Phases

| Phase | Work | Repos | Done when |
|---|---|---|---|
| **P0a** | This RFC | api docs | Merged |
| **P0b** | Tenable.sc client, connector config loader, `connector_sync` handler, mapping, fake server and golden tests, manifest capability | sensor | Fake-server suite green; sensor PR open against `main` |
| **P0c** | Command types, integration validation for `tenable_sc` + sensor mode, `POST /integrations/{id}/sync`, completion hook (cursor, stats), sync controller | api | Cross-tenant and refusal tests green |
| **P0d** | Mitigated resolve gate, tool registration, golden ingest test | api | Three modes tested |
| **P0e** | End-to-end run; un-hide the integration page with sync status | web, api | §12.5 passes |
| **P1** | `connector_scan` (sensor), RFC-046 engine `tenable_sc`, probe gate, scan dialog, catalog pull of policies/repositories/asset lists | sensor, api, web | A launched scan's findings ingest with full coverage for its targets only |
| **P2** | Coverage on runs, license numbers, Coverage panel back | api, web | Rolling coverage over a fake 3000-IP estate with a 500-IP license never exceeds headroom |
| later | Signed envelopes for connector commands (RFC-040 P1), credential references, RFC-044 catalog import of plugins, tenable.io / Nessus Pro engines | all | — |

## 15. Owner questions

| # | Question | Options | Recommended |
|---|---|---|---|
| Q1 | Where do the Tenable allow-lists live? | (a) the connector's own config file (§6.1); (b) a `connectors.tenable_sc` section of `sensor-policy.yaml` | **(a)** for P0: the policy schema stays generic and the connector owns its keys and limits; both are owner-written, read-only files. Revisit when a second connector exists |
| Q2 | Who owns scan schedules? | (a) OpenCTEM (RFC-046 rrule) launches on demand; (b) OpenCTEM creates Tenable.sc iCal schedules | **(a)** |
| Q3 | Mirror Tenable accept-risk / recast into OpenCTEM statuses? | (a) keep as facts only; (b) per-integration opt-in mirror to `accepted` / severity override | **(a)** in P0; (b) later as an opt-in with audit |
| Q4 | License reclaim | (a) none, Tenable aging only; (b) an allow-listed `reclaim` operation that removes a batch's data from a dedicated rotation repository after ingest confirms it | **(a)** in P2; (b) only if a customer needs it |
| Q5 | Overlapping IP spaces across repositories | (a) one IP asset per tenant, warn on collision; (b) map each Tenable repository to an OpenCTEM scan zone and key IP assets by zone (RFC-042 zone-keyed identity) | **(a)** now, **(b)** with RFC-042 P1 |
| Q6 | Informational plugins | (a) off by default (`min_severity: 1`); (b) on | **(a)**; info rows can be enabled per integration |
