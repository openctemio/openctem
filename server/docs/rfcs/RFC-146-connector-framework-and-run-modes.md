# RFC-146: Connector framework and run modes

| | |
|---|---|
| Status | Proposed (2026-11-02). Implemented today: the Tenable.sc sensor connector, the asset collector, CTIS ingest and the file importers, Jira two-way and GitHub Issues, the notifier channels. Designed here: the shared connector kit, the connector instance model, sync semantics, the declarative REST connector, signed connector packs, the connector roadmap |
| Scope | sdk-go (`pkg/connector`), ctis (capability keys, identifier kinds), sensor (cloud and Kubernetes collectors), connector images, api (instance model, multi-source observations, ticket engine, webhooks), vulnfeed |
| Related | RFC-013 (DefectDojo co-existence), RFC-040 (signed jobs), RFC-047 (Tenable.sc connector), RFC-049 (unified connector framework), RFC-055 (tool contract), RFC-069 (attribute reconciliation), RFC-074 (adaptive sensor control), RFC-142 (feed relay) |
| Supersedes | RFC-049 section 7 (mode per tenant per connector, `platform` mode for pull connectors) |

## 1. Summary

OpenCTEM reads from many systems (clouds, vulnerability scanners, endpoint and cloud-security products, code hosts,
intelligence feeds) and writes to many (trackers, chat, SIEM, patch and WAF tooling). This RFC fixes how, once, so
that each new integration is a small piece of mapping code and not a new subsystem:

1. **Three run modes and no fourth** (section 3).
2. **One connector kit in sdk-go** that every connector uses, built-in or third-party (section 4).
3. **Natural-key matching** across sources and **per-attribute precedence** from RFC-069 (section 6).
4. **"Not seen" is not "fixed"** (section 5).
5. **Two-way ticket ownership by field** (section 7).
6. **A declarative REST connector** for the long tail (section 8).
7. **Signed connector packs at three trust levels** (section 9).
8. **A prioritised connector list** (section 11).

## 2. Current state

Verified in code on 2026-11-02.

| Area | State |
|---|---|
| Sensor pull connectors | Tenable.sc (`connector-tenable`: `connector_sync`, `connector_scan`, capability `network_va.connector`), credentials stay on the sensor |
| Asset collectors | vCenter, LDAP, Cloud DNS, PRTG, Splunk inventory (asset-collector add-on) |
| Cloud inventory | **Not shipped.** `server/internal/app/connector/connector.go` is a framework with an AWS scaffold and no provider code; the Azure and Kubernetes provider constants have no adapter |
| File and push import | CTIS ingest, sdk-go, 18+ importers (Nessus, Qualys, DefectDojo, CycloneDX, SPDX, OSV, CSAF, OpenVEX, SARIF, trivy, nuclei, semgrep, opengrep, gitleaks, grype, vuls, ZAP, bounty reports), generic CSV/JSON/JUnit mappings |
| Ticketing | Jira two-way and **GitHub Issues**. There is no GitLab Issues, Azure Boards or ServiceNow tracker |
| Other downstream | Slack, Teams, Telegram, email, signed webhook, Splunk HEC, admin audit syslog, finding CSV/NDJSON export, SBOM export, MCP server |
| CI | GitHub, GitLab, Azure Pipelines, Bitbucket, CircleCI and Jenkins OIDC providers |
| Inert code | `pkg/domain/integration/entity.go` carries provider constants (Wiz, Snyk, CrowdStrike, Linear, Asana, AWS, GCP, Azure) that no code path uses |

## 3. Run modes

| Mode | Used for | Credentials live | Network egress from |
|---|---|---|---|
| **Sensor-run pull** (connector job or collector) | every upstream source: cloud, scanners, endpoint and cloud-security products, code-host alerts, intelligence with the tenant's own key | the sensor (files, environment or secret references) | the sensor |
| **Platform request/response** | downstream only: ticketing, ITSM, chat, SIEM push, webhooks, WAF and patch hooks | the platform, encrypted at rest; the integration encryptor fails closed in production | the platform's egress gateway, a platform-owned sensor role (RFC-142) |
| **Push in** | CTIS ingest, CI, file import, inbound webhooks, MCP | the caller's own token (sensor key, CI run token, API key) | none |

Rules:

- No new pull connector runs inside the API process. The existing DefectDojo sync and the bounty-platform scope
  fetch move to sensor-side jobs (both already emit CTIS).
- A two-way system splits along the two modes: its read side is a sensor-run pull, its write side is platform
  request/response.
- For a SaaS source reached from a managed deployment that has no customer sensor, a managed connector executor
  runs the same connector; the credential is sealed to that executor per job (`sdk-go/pkg/sealedmsg`) and is never
  stored there. Self-managed installations do not need it.
- This supersedes RFC-049 section 7: a pull connector never runs in `platform` mode. The connector contract and
  descriptor in RFC-049 section 5 stay.

## 4. The connector kit (`sdk-go/pkg/connector`)

Mechanisms live in sdk-go so every connector gets them, and built-in connectors use the same public contract as a
third-party one (no special case). Most parts exist and are assembled, not written.

| Concern | The kit provides | Reuses |
|---|---|---|
| Interface | `Describe() Manifest`, `Check(ctx) Health`, `Sync(ctx, Cursor, Emit) (Cursor, error)`; `Emit` takes CTIS asset and finding batches | ctis types |
| HTTP | client with SSRF guard pinned to declared hosts, redirects off, body caps, safe JSON/XML decoding | `pkg/httpsec`, ctis importer guards |
| Pacing | per-source token bucket that slows on latency, 429 and 503, quiet windows | `pkg/adapt` source pacer |
| Retries | backoff and circuit breaker | `pkg/retry` |
| Pagination | helpers for offset, page token, link header, cursor in body, time windows | new, small |
| Incremental sync | cursor persisted per connector instance; full and delta runs | `pkg/localstore` |
| Delivery | durable outbox, resumable after an outage | `pkg/outbox` |
| Secrets | file, environment and secret-reference providers; never in argv or logs; redaction helper | asset-collector pattern |
| Health | last success, error class, records in and out, cursor age, rate-limit state, reported in the sensor heartbeat | sensor heartbeat |
| Data minimisation | per-connector field allow-list; configuration may narrow it, never widen | asset-collector rule |
| Testing | recorded-fixture transport with scrubbed cassettes, golden CTIS, mapping coverage gate, decoder fuzzing, conformance suite | `pkg/testkit`, `pkg/conformance`, ctis field-coverage test |

The manifest declares the capability (`network_va.connector`, `cloud_inventory.collector`, `edr.connector`, ...),
the data classes emitted, the **egress hosts** (used by the sensor's egress confinement and shown to the
administrator), the read-only vendor permissions required (for example `SecurityAudit` on AWS, `Reader` on Azure,
`Cloud Asset Viewer` on GCP), the sync modes and the option schema.

## 5. Sync semantics

- **Full sync** asserts the complete set for its scope (account, subscription, cluster, scanner repository). An
  asset the source no longer lists becomes `stale` for that source only.
- **Delta sync** never marks anything stale. A periodic full run (default weekly, adaptive per RFC-074) reconciles.
- A source that fails or returns a truncated set (a shrink guard with a 0.90 floor, as the vulnerability feed uses)
  marks nothing stale.
- **Not seen is not fixed.** A finding closes on one source's "fixed" or absence only when no other active source
  still reports it, or validation proves the fix. Otherwise the finding shows "not seen by X since ...".

## 6. Identity, correlation and precedence

- **Cloud resources** use provider-native identifiers: AWS ARN or instance id with the account, Azure resource id,
  GCP full resource name, Kubernetes UID with the cluster id. They are deterministic, so a rebuild or a second
  collector yields the same key.
- **Hosts across tools** resolve through `assetresolution` on several identifiers (cloud instance id, endpoint
  agent id, MAC, FQDN, directory object id, IP with a time window).
- **Findings across tools** key on the canonical vulnerability id (CVE through the alias rule), the asset and the
  locus (port and service, package purl and version, file and rule). When a scanner gives only its own plugin id,
  that id is kept as a secondary key. Each source keeps its own observation (first seen, last seen, severity, raw
  id) under the merged finding, so provenance and "seen by N sources" are visible.
- **Precedence** is the RFC-069 attribute policy, tenant-editable. The default for host facts: cloud API, endpoint
  agent, CMDB, MDM and directory, authenticated scanner, unauthenticated scanner, passive discovery. For owner,
  business unit and criticality: CMDB, then manual, then CSV (a manual lock always wins). Severity stays per
  source; the platform score is computed and never copied from a vendor's risk score. Every value shows its source
  and age.

## 7. Two-way sync (tickets and ITSM)

- **Ownership by field.** The platform owns finding state, severity and evidence. The tracker owns ticket status,
  assignee and comments. The per-integration mapping sends the tracker's "done" to the finding event **fix
  claimed**, which triggers a retest; the finding resolves only after validation or per the tenant's closure mode.
- **Loops.** The echo guard that exists for Jira applies to every tracker, and each outbound write carries an
  idempotency key.
- **Inbound webhooks.** A secret per integration (never global), an HMAC over body and timestamp, a five-minute
  replay window, and the tenant taken only from the integration record, never from a query parameter.
- **Conflict.** When both sides changed the same owned field since the last sync, the owning side wins and the
  other side receives a comment. Nothing flaps.
- ServiceNow uses the same ticket engine as Jira (the adapter engine, generalised), not a parallel one.

## 8. Declarative REST connector

A YAML specification run by the kit: authentication (API key header, basic, OAuth2 client credentials, bearer),
pagination style, endpoints, JSONPath mapping to CTIS fields, a severity map and identifiers. Limits: GET and POST
only, only to hosts declared in the specification, no scripting, no URL built from response data toward another
host, response size caps. Specifications are content (signed packs, section 9) and can be authored in the console
with a dry run against a recorded sample. The mapping engine is shared with `importmapping`, so a CSV mapping and a
REST mapping use one field vocabulary.

## 9. Third-party connectors

The contract is the tool contract (RFC-055) plus the kit manifest.

| Trust level | Rule |
|---|---|
| Community | unsigned or self-signed; a tenant administrator must allow it explicitly; runs only on that tenant's own sensors |
| Verified | passes the conformance suite in CI and is signed by a registered publisher key; listed in the content hub |
| Built-in | signed by the project key and shipped in the sensor image |

Third-party code never runs in the platform. Connectors are distributed as signed sensor tool packs
(`sdk-go/pkg/tool/pack`) listed in the content hub, with version ranges against the sensor protocol. Developer
experience: a `connector init` scaffold, a local runner against a recorded cassette, a conformance command, and a
documentation template that lists the required vendor permissions.

## 10. Packaging

Source connectors (inventory and findings) and the connector kit are part of the open core. Integrations with
enterprise systems of record (ServiceNow ITSM and CMDB, a SIEM pack with event streaming, GRC
export, scheduled warehouse export, WAF and patch hooks) belong to the Enterprise overlay. The asset collector
remains a separate add-on for the on-premises estate (vCenter, directory, monitoring, MDM). Curated early-warning
intelligence is separate premium content. Managed connector executors exist only in a managed deployment.

## 11. Connector list and roadmap

Order of work (the kit lands first; each item after it is small):

1. Cloud and cluster inventory: AWS, Azure, GCP, Kubernetes (sensor collectors, read-only roles).
2. Scanner API pulls: Tenable Vulnerability Management and Nessus, Qualys VMDR, Rapid7 InsightVM (reusing the ctis
   importer mappings).
3. Code-host alerts: GitHub code scanning, Dependabot and secret-scanning metadata (no secret values), GitLab
   security reports in the CI job.
4. Intelligence in the signed feed: exploit availability, OSV and GHSA advisories, used as a prioritisation input.
5. Endpoint and cloud-security sources: Defender Vulnerability Management and CrowdStrike Spotlight (with device
   lists as host anchors), Wiz, AWS Security Hub.
6. The declarative REST connector.
7. Trackers on the generalised ticket engine: GitLab Issues, Azure DevOps Boards, then ServiceNow (Enterprise).
8. OCSF export, then the SIEM pack (Enterprise).

Phase 0 (foundations) precedes all of them: the kit in sdk-go (interface, HTTP client, cassette testing), ctis
capability keys and identifier kinds, the connector instance model in the console (per tenant, bound to a sensor,
schedule, sync mode, health from heartbeat), multi-source finding observations with the closure rule, default
precedence for the new source kinds, per-integration webhook secrets with a replay window, removal of the inert
provider constants, and the integration encryptor failing closed in production.

## 12. Security

| Area | What must hold |
|---|---|
| Credentials | only on the sensor, or sealed per job to a managed executor; never in the platform database for sensor-run sources; redaction tests; read-only vendor roles documented and checked by `Check()` where the vendor exposes granted scopes |
| SSRF and egress | host pinning to declared hosts, no redirects, private ranges only when the operator lists the CIDR, declarative specifications cannot reach undeclared hosts |
| Tenant isolation | the connector instance's tenant comes from the sensor grant; ingest tenant comes from the principal only; cross-tenant negative tests on the instance API and on emitted reports |
| Webhooks | secret per integration, HMAC with timestamp and replay window, tenant from the integration record |
| Write actions | any write to a customer system (ITSM, WAF, patch tooling) needs approval and an audit record; WAF and patch hooks need two-person approval and a dry run |
| Hostile vendor data | size caps, safe decoders, the CTIS report guard; untrusted text is never rendered as HTML or sent to AI without masking |
| Supply chain | signed packs, publisher keys, version ranges; community connectors only on the tenant's own sensors |

## 13. Alternatives considered

- Connectors inside the API (classic aggregator): fastest, rejected because it breaks zero platform egress and
  credential locality. Kept only for downstream request/response through the gateway.
- Embedding DefectDojo permanently for breadth: rejected (RFC-013); it stays a replaceable input adapter.
- A third-party unified-API service for breadth: rejected, because it puts an outside data processor in the path of
  findings and adds platform egress.
- One process per vendor: rejected as the default; one image per family on the shared kit keeps release cost low,
  and a vendor that needs credential isolation runs its own instance of the same image.
- A packaged SOAR actions marketplace now: rejected; REST and signed webhooks cover it today.

## 14. Open items

- Rename of `connector-tenable` to a vendor-neutral name waits for an owner decision.
- The Cloud DNS duplication between the open sensor's GCP collector and the asset collector is removed from the
  add-on in its next minor release.
