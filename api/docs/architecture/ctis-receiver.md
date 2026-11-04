# CTIS 2.0 receiver

> **Status**: Implemented (2026-11-03). The platform accepts CTIS 2.x only.
> Specification: the `github.com/openctemio/ctis/v2` module (`docs/spec.md`,
> `docs/migration-2.0.md`, `docs/profiles/openctem.md`). Orchestration
> contracts (capabilities, tool options, settings, outcomes, politeness,
> edge protection, address scope, sources, feed transfer) live in
> `github.com/openctemio/contract`. The standard formats (SARIF, CycloneDX,
> SPDX, CSAF, OpenVEX) are adapter modules
> `github.com/openctemio/ctis/v2/interop/<format>`, registered with the CTIS
> importer in one place (`internal/app/ctisformats`).

## What the platform accepts

Every path that applies a CTIS document — sensor protocol v2 results, a
queued v1 job left over from before, a CI run upload, a finding import
(native CTIS or converted by an importer or an import mapping), a DefectDojo
sync, the program target and certificate promotion reports the platform
builds itself, and the acceptance of a quarantined report — goes through the
same rules:

1. **Decode** (`ingest.DecodeStrictReport`): the I-JSON pre-pass with item
   bounds runs first, then `ctis.Decode`. The document must declare CTIS 2.x.
   A 1.x document is refused (`ErrCTISVersion`; on protocol v2 the problem is
   `version-mismatch` with the detail "this platform accepts CTIS 2.x only:
   upgrade the sensor, connector or CI integration"). The body is the
   document itself: the CI results route and the job result parser refuse a
   `{"report": ...}` envelope (on the CI route, `400` naming the upgrade).
   A document of this
   minor or an older one is decoded strictly (an unknown member is refused);
   a newer 2.x minor is decoded with version-gated must-ignore (unknown
   members ignored, unknown enum values mapped to their fallback).
2. **Validate** (`ctis.Report.Validate`, also run by `ingest.Service.Ingest`
   for every path): `metadata.id` is a producer-generated UUIDv7; document
   references (`asset.id`, `*_ref`) are never UUID-shaped; every asset value
   is in the canonical form of its type; every finding names an asset of the
   document (`asset_ref` is required); URL members are http(s); extension
   namespaces the module knows are validated.
3. The protocol v2 media type is `application/vnd.ctis+json; version=2.<minor>`
   (`protov2.MediaTypeCTIS` sends `version=2.0`).

## No receiver keys in a document

A document carries canonical natural keys and the producer's own references
(`source_refs`), never one of the platform's database ids.

- `metadata.id` is the producer's idempotency key. The platform never uses it
  as one of its own ids. The receiver's report id (the scan identity of the
  findings a report writes) comes from the transport: the protocol v2 report
  id of the URL path, the import receipt, the queued job, the CI upload
  (`ingest.Input.ReportID`; empty means a new id for the ingest).
- The command or delivery a document answers is bound by the transport
  (`/commands/{command_id}/results/{delivery_id}`), not by the document.
- Asset and finding ids are resolved from natural keys at ingest: assets by
  (tenant, stored type, canonical name), findings by the platform's own
  recomputed fingerprint. A producer's `fingerprint` is a hint only.
- The platform's own producers follow the same rule: the DefectDojo
  converter, the certificate promotion and the program target ingester put a
  fresh UUIDv7 in `metadata.id` and no tenant, program, integration or import
  id anywhere in the document.

## Wire types and the stored model

The stored asset model does not change. The CTIS 2.0 wire types map onto it
in the receiver (`mapCTISAssetType` in `internal/app/ingest/mappers.go`).
The wire-only names are not `type_inputs` of `configs/asset-types.yaml`, so
the REST API's asset type inputs stay as they were:

| Wire type | Stored as |
|---|---|
| `domain_name` | `domain` when the name is its public-suffix apex (example.com, example.co.uk), else `subdomain` |
| `web_origin` | `service` / `http` |
| `service` (`host:port/transport`) | `service` / `open_port` |
| `host`, `ip_address`, `certificate`, `repository`, ... | the stored type of the same name |
| `identity` + `technical.identity.kind` | `identity` / `iam_user`, `iam_role`, `service_account` (other kinds kept as the native sub-type) |
| `ip_range` | `network` |
| `network_device` + `technical.network_device.kind` | `network` / `router`, `switch`, `firewall`, `load_balancer`, `vpn_gateway`, `access_point` |
| `kubernetes_cluster`, `kubernetes_namespace`, `kubernetes_workload` | `kubernetes` / `cluster`, `namespace`, `workload` |
| `container_image` | `container` / `image` |
| `endpoint_device` | `host` / `workstation` |
| any other type | `unclassified` |

An asset is stored under `asset.NormalizeName` of its canonical **value**;
`name` is a display label and never the identity.

## Properties carry no meaning

CTIS 2.0 receivers MUST NOT read behaviour from `properties`.
`adoptCTIS2Members` (`internal/app/ingest/ctis2_members.go`) runs once per
ingest, after validation:

- it strips from every asset's properties the keys the platform used to
  interpret (sub-type, kind, root domain, exposure, aliases, technologies,
  zone visibility, last seen, discovery source and tool, web content, import
  scope, candidate exposure, certificate fields, owner, HTTP posture and
  response fields, hypervisor host, every IP address key);
- it derives the keys the stored model keeps from typed members:
  `ip_addresses` of a name from its A/AAAA DNS records and its `resolves_to`
  relationships (DNS only); `ip_addresses` of a machine (network device,
  host, endpoint device, any asset that is not a name, an address or a
  range) from its `has_address` relationships (ctis v2.0.1: interface or
  management addresses), which is what network device matching reads; a
  range never records addresses, so a segment is never matched by address; `root_domain` of a subdomain only from a `subdomain_of`
  relationship of the document (never from the public suffix list, so a
  sensor cannot make the platform create a registrable domain it did not
  name); `import_scope`, `candidate_exposure`, `candidate_unverified` and
  `web_content` from `extensions["io.openctem"]`.

Only a report the platform builds from its own data keeps its properties:
the certificate promotion, which marks its ingest `ServerBuilt` (honored
only with no sensor, no CI run and no uploader). Every other report loses
the interpreted keys: every sensor report, a CI run, a person's upload
(restricted or not), a connector's conversion (DefectDojo) and program
targets (which set none). Whatever a producer leaves
under other keys is stored as an opaque, display-only, bounded attribute bag.

Typed members that replaced properties:

| Fact | CTIS 2.0 member |
|---|---|
| Open ports | one `service` asset per port + `exposes` relationship |
| HTTP response facts | `technical.http` (status code, title, server, CDN, WAF, JARM, favicon, TLS version) |
| Security headers | `technical.http.security_headers`, stored as the `http_posture` flags (never a header or cookie value) |
| Technologies | `asset.technologies` |
| Last seen by the source | `asset.last_seen_at` |
| Private DNS zone | `domain_name` with `is_internet_accessible: false` |
| Owners | `asset.owners` |
| Capability of the report | `metadata.extensions["io.openctem"].capability` (a hint; the output binding writes the bound capability) |
| Scanner ignore file of a CI run | `metadata.extensions["io.openctem"].ignore_file_paths` |
| Template provenance | `rules[].content_sha256`, `rules[].content_path`, `rules[].extensions["io.openctem"].rule_source`, `tool.content[]` |
| Scanned container image of a CI run | a `container_image` asset (`registry/repo@sha256:digest`) |

## Findings

- Source: the report's bound capability (the command's, never the
  producer's claim); unbound, `finding.technique`, else the first of
  `tool.techniques` (closed vocabulary), else the tool name; unknown is
  `external`. `finding.technique` never moves a bound report's finding to
  another source; a known technique is recorded apart in the finding's
  metadata (`technique`). The channel is the principal's, never the document's.
- Vulnerability ids: `vulnerability.ids[]`. A finding is keyed on its
  preferred CVE (numerically smallest); a network or SCA finding naming
  several CVEs is split per CVE as before.
- Scores: the primary CVSS of `scores[]` (`ctis.PrimaryCVSS`); the vendor
  score of source `tenable` is the VPR shown on the finding. Threat signals
  (`public_exploit`, `weaponized`, `exploited_in_wild`) set the scanner's
  exploit verdict; KEV and EPSS still come from the platform's own feeds.
- Evidence: `evidence_items[]` only (`raw_text` is the scanner output).
- Rule catalog: a finding with `rule_ref` takes the rule's name and
  description when it has none; never part of an identity.
- Removed (receiver-derived or gone from the format): impact, likelihood,
  business impact, the remediation context (merged into `remediation`),
  web3 as a finding type, `asset_value`/`asset_type` on a finding.

## Stored data

- **Findings**: the identity re-key to fingerprint recipe v2 is the finding
  identity migration (`finding_rekey_runs`, `cmd/refingerprint`); see
  `docs/architecture/deduplication.md`.
- **Asset names**: `internal/app/assetcanon` moves a stored asset name to the
  name the CTIS 2.0 ingest gives the same asset (IDNA A-labels, URL paths
  with dot segments removed and percent encoding normalized, the expanded
  image digest form). It renames the asset, or, when an asset of the same
  tenant, type and sub-type already holds the name, merges it into that
  asset through the asset merge (every reference moves, findings are
  re-keyed and folded). An asset whose canonical name another type holds is
  left and recorded. Every change is per tenant, in one transaction per
  asset, re-checked under row locks, and journaled in
  `asset_canonical_changes`. The server runs it on start; the
  `asset-canonical` command runs it dry (default), for one tenant, or
  reverts the renames. Operator steps: `docs/operations/ctis-2-upgrade.md`.
- **Import mappings**: documents are `openctem.io/mapping/v2`; a stored v1
  mapping is refused when loaded and must be rewritten with the 2.0 member
  names.

## Threat model

| Threat | Control |
|---|---|
| A hostile or compromised producer sends a 1.x document to slip past 2.0 checks | Refused by version before decoding (`ErrCTISVersion`); there is no downgrade path |
| A document plants a platform UUID (tenant, asset, scan) as `metadata.id` or a reference | Validate refuses UUID-shaped references; `metadata.id` is never read as a platform id; the receiver's report id comes from the transport |
| A producer uses `properties` to steer the platform (sub-type, root domain, exposure, scope addresses) | Stripped before anything reads them for every external report |
| A producer claims a capability or channel to widen what it may write | The output binding uses the command's capability; the channel comes from the authenticated principal |
| Two spellings of one name (Unicode vs A-label, path dot segments) split or alias an asset | Canonical values are required on the wire; stored names are migrated to the same canonical form |
| The asset-name migration crosses tenants or merges different things | Every query is tenant-scoped; a merge needs the same tenant, type and sub-type, re-checked under row locks; another type holding the name is a recorded conflict, never a merge |
| A merge loses triage | The asset merge moves every reference and folds findings keeping the strongest status and their history (`asset_merge_findings.go`) |
