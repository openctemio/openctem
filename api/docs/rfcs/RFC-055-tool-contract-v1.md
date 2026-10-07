# RFC-055: Tool Contract v1 (capabilities, descriptors, inputs and outputs of every sensor tool)

| | |
|---|---|
| Status | Accepted (owner delegated 2026-10-07: TC1–TC16 as recommended) |
| Scope | ctis (`capability`, CTIS 1.5, `importer/mapping`), sdk-go (`pkg/tool`, runtime, `cmd/openctem`, `pkg/conformance`), sensor (built-in tool descriptors, parsers), api (`pkg/domain/stage`, `pkg/domain/sensor`, ingest, `tools`), web (workflow builder palette and forms) |
| Architecture | [tool-contract.md](../architecture/tool-contract.md), [scan-stages.md](../architecture/scan-stages.md) |
| Related | RFC-033 (sensor manifest), RFC-038 (tool config schema), RFC-040 (mutual distrust), RFC-046 (scans redesign, stage catalogue), RFC-049 (connector framework), RFC-052 (grants and tier ceilings), RFC-054 (scope authority); sdk-go `docs/rfcs/sensor-sdk-v2.md` (the tool contract runtime this RFC extends) |

## 1. Summary

The facts about a scan tool have been declared in about fourteen places. They
use four capability vocabularies, and these disagree:
- the sensor's capability words;
- the SDK's word list;
- the platform's `capabilities` table and `tools.capabilities`;
- the stage catalogue ids.

None of the built-in tool manifests named a catalogue capability. As a result:
- the platform mapped tools to capabilities with hard-coded per-tool tables;
- parsers existed in three copies;
- adding a tool touched three repositories and about twelve files.

This RFC makes one standard out of them:

1. **A capability is the vocabulary.** A closed, versioned taxonomy
   (`scan.ports@1`, `probe.http@1`, …) lives in one place,
   `github.com/openctemio/ctis/capability`. The capability carries:
   - the phase and CTEM stage;
   - the tier floor;
   - typed ports;
   - standard params;
   - required CTIS output;
   - MITRE ATT&CK, D3FEND and CAPEC references.

   A tool cannot invent or redefine any of these (TC1, TC2).
2. **A tool is a `tool.yaml` descriptor plus a program.** The descriptor
   declares which capabilities the tool `implements`, what CTIS types it
   consumes and produces, and:
   - its batch shape;
   - its config schema;
   - its permissions and safety facts;
   - how it runs;
   - its self-test fixtures.

   Tools never declare ports (TC3). Built-in tools use the same embedded
   `tool.yaml` format as third-party tools (TC4).
3. **The platform assigns the tier and the trust level** (TC1, TC8, TC16).
   The tool's own tier is a request that can only raise the tier.
4. **Every output is CTIS from one parser library**, `ctis/importer` (TC5),
   or from a declarative mapping for JSON tools (TC6). Output is checked
   twice: by the SDK runtime and by the platform.
5. **One developer path.** Most tools need no Go: a descriptor around a CLI
   that writes SARIF, CTIS, a known format, or JSON with a mapping file. One
   CLI, `openctem tool init | validate | run | test | diff | describe`, and a
   conformance kit define what "certified for `scan.ports@1`" means.

The goal: a future tool implements one SDK interface or adapter, and works
with the platform with no platform change. The only exception is a tool that
implements a capability that does not exist yet.

## 2. Problem

| # | Finding | Effect |
|---|---|---|
| D1 | Four capability vocabularies; no built-in manifest names a catalogue id | Capability nodes cannot be served from what sensors report; a third-party tool cannot implement `scan.ports@1` |
| D2 | Reported capabilities come from legacy scanner words, not the tool manifest | The manifest the runtime enforces is not the one the platform plans with |
| D3 | nuclei declares `dast`; the catalogue routes it to `vuln.templates` | Ambiguity; wrong finding source |
| D4 | Outputs drift between sensor manifests and the catalogue; gaps filled by platform derivations keyed on tool names | A different port scanner gets no `open_port`/`exposes` derivation |
| D5 | Inputs drift (katana takes domains, `crawl.web` takes URLs; a third vocabulary in `tools.supported_targets`) | Builder and dispatch disagree |
| D6 | Param mapping duplicated three times; seven tools have no config schema | Workflow params silently unavailable for most tools |
| D7 | Batch shape is a platform map | A new batch-capable tool runs one target per task |
| D8 | Parsers in three copies | A fix to one copy misses the others |
| D9 | codeql ships in the sensor but has no `tools` row | Invisible to enablement and availability |
| D10 | Tier declared twice, used once; no path to classify a third-party tool | Third-party tools are permanently T2 |
| D11 | Every built-in adapter is version `1.0.0` | Version-based caching is unsafe |
| D12 | Required output fields are abstract names | Not testable, not checkable at ingest |
| D13 | CTIS has no typed relationships, no technique ids, untyped technologies | Relations rebuilt per tool; no ATT&CK traceability |
| D14 | Retest/validate advertised as ad-hoc strings (`retest:<tool>`, `validate:nuclei`) | A fifth capability channel |

## 3. The capability taxonomy (`ctis/capability`)

The taxonomy is embedded JSON (`capability/taxonomy.json`). It is validated
when the package loads, and the reference page `docs/capabilities.md` in the
ctis repository is generated from it.

### 3.1 Model (TC1)

```
capability (WHAT, closed, id@major)
  ├─ phase        discover.passive | discover.active | assess | validate | collect
  │               → CTEM stage (discovery | validation)
  ├─ tier_floor   0 passive | 1 active | 2 intrusive
  ├─ in_ports / out_ports   closed port types, each carrying CTIS asset types
  ├─ extra_outputs          kinds that ride along without a port ("asset:certificate", "dependency")
  ├─ finding_types          allowed finding types (empty = any) when out_ports has finding
  ├─ params                 standard params (string, string_list, integer, boolean, port_list; enum; min/max)
  ├─ outputs                required-output rules (§3.3)
  ├─ attack / d3fend / capec
  ├─ status       routed | planned | later
  ├─ cross_cutting           used by other flows (retests, imports), never a workflow node
  └─ deprecated   {since, replaced_by, message}
```

Phase, techniques and the tier floor are properties of the act, so they
belong to the capability:
- an active port scan is ATT&CK T1595.001 / T1046 and CTEM Discovery,
  whoever performs it;
- a tool cannot declare these facts wrongly, and they cannot drift;
- the platform reports coverage by technique without trusting tool input.

A tool that performs several acts implements several capabilities.

### 3.2 Port types

The closed set of port types:

| Port | CTIS asset types carried |
|---|---|
| `root_domain` | `domain` |
| `hostname` | `domain`, `subdomain` |
| `ip` | `ip_address`, `host` |
| `cidr` | `network`, `subnet` |
| `service` | `open_port`, `service` |
| `url` | `http_service`, `discovered_url`, `website`, `api`, `web_application` |
| `repository` | `repository` |
| `container_image` | `container` |
| `cloud_account` | `cloud_account` |
| `finding` | (sink; input only to `verify.finding`) |

- `Accepts(assetType)`: an input port carries the type.
- `MayEmit(kind)`: true for kinds the output ports carry, kinds the input
  ports carry (a tool re-observes its targets), the extra outputs, and
  findings of an allowed type.

### 3.3 Required output rules (fixes D12)

A rule has the form `{shape?, select, paths?, any_of?}`:

- `select` is `assets`, `findings` or `dependencies`, with an optional type
  filter: `assets[type=ip_address|host]`, `findings[type=secret]`.
- `paths` are dotted CTIS JSON member names relative to the record. `[]`
  after a member means the list must be non-empty and the rest of the path
  applies to every element (`technical.domain.dns_records[].type`).
- Every selected record must carry every path, and at least one `any_of`
  path. A path is present when its value is not null, `""`, `[]` or `{}`.
- A rule that selects no record is satisfied: an empty result is a valid
  result.
- `shape` names one of several accepted output shapes. `scan.ports` accepts
  either:
  - `open_port_assets`: one `open_port` asset per port;
  - `ip_ports`: ports on the IP asset.

  A tool that declares its shape is checked against that shape's rules and
  the unnamed rules only.
- Every path must resolve against the CTIS Go types when the package loads.
  Members of free-form maps (`properties`, `details`) may carry any key
  below them.

`Capability.Check(report, opts)` returns `not_allowed`, `missing_path` and
`missing_any_of` violations. It is bounded (100 by default) and never
modifies the report. The SDK runtime runs it before upload, and the platform
runs it again at ingest.

### 3.4 Taxonomy v1 (29 entries)

- **Routed:**
  - `discover.subdomains` (T0);
  - `resolve.dns` (T0);
  - `scan.ports` (T1);
  - `probe.http` (T1);
  - `crawl.web` (T1);
  - `vuln.templates` (T1);
  - `dast.web` (T2);
  - `sast.code` (T0);
  - `secrets.code` (T0);
  - `sca.deps` (T0);
  - `iac.misconfig` (T0);
  - `container.image` (T0);
  - `network_va.connector` (T1);
  - `import.file` (T0, cross-cutting).
- **Planned:**
  - `intel.passive`;
  - `detect.services`;
  - `fingerprint.tech`;
  - `check.tls`;
  - `capture.screenshot`;
  - `discover.cloud`;
  - `sbom.generate`;
  - `cloud.posture`;
  - `host.credentialed`;
  - `verify.finding` (cross-cutting, modes `retest` and `exploit_check`);
  - `check.takeover`.
- **Later**, listed only, each with a trigger:
  - `discover.repositories`;
  - `config.benchmark`;
  - `check.credentials`;
  - `simulate.attack`.
- Excluded on purpose:
  - brute force and default logins;
  - fuzzing as its own capability (it is the T2 mode of `vuln.templates` and
    `dast.web`);
  - people and e-mail OSINT.

Every id the platform's stage catalogue used before this RFC is kept
unchanged. The routed standard params equal the platform contracts, and a
ctis test pins them.

## 4. The descriptor (`tool.yaml`, `openctem.io/tool/v1`, additive)

`v1` stays the apiVersion: every new key is optional. A descriptor that uses
a new key needs an SDK that knows it, declared with `sdk.min`.

```yaml
apiVersion: openctem.io/tool/v1
name: naabu                         # ^[a-z][a-z0-9-]{1,62}$
version: 2.0.0                      # adapter semver; `openctem tool diff` enforces bumps
description: Fast TCP connect port scanner.
publisher: openctemio
license: MIT
engine: {name: naabu, license: MIT, min_version: 2.3.0, version_probe: [naabu, -version]}
presentation: {display_name: Naabu, category: network, icon: radar, docs_url: https://docs.openctem.io/tools/naabu}
class: target-scan                  # target-scan | connector | parser | enricher
tier: T1                            # a request; the platform assigns (§5)
implements:
  - capability: scan.ports@1
    params:                         # standard param → this tool's config key, and the subset it supports
      ports:    {key: ports}
      top_n:    {key: top_ports}
      rate:     {key: rate, max: 5000}
      protocol: {values: [tcp]}     # a value outside → the tool is ineligible for that node
    output_shape: open_port_assets
consumes: [domain, subdomain, ip_address, host]          # ⊆ the capability's in-port carries
produces: [asset:ip_address, asset:host, asset:open_port] # ⊆ MayEmit
input: {batch: list, max_targets: 5000}                   # replaces the platform's batch map
config: {type: object, additionalProperties: false, properties: {…}}  # RFC-038 subset
permissions: {network: targets, proxy: honours, filesystem: workdir, credentials: [], linux_caps: []}
resources: {cpu: 1, memory: 512Mi, timeout: 6h, idle_timeout: 10m, max_output_bytes: 64Mi, max_records: 200000}
safety: {rate_param: rate, side_effects: [], expands_targets: false}
features: {retest: false, cancel: true, streaming: false}
run:                                # absent for a Go tool compiled into the sensor
  profile: exec                     # adapter | exec
  argv: [naabu, -list, "{{task.targets_file}}", -json, -silent]
  output: {format: jsonl, from: stdout, mapping: mapping.json}
  exit_codes: {"0": ok}
selftest: [{name: two-open-ports, task: fixtures/task.json, expect: fixtures/expect.ctis.json}]
protocol: {min: 1}
sdk: {min: 0.20.0}
deprecated: {since: 2.1.0, replaced_by: other-tool, message: …}
artifact: {digest: "sha256:…", signature: bundle.json}   # certified tools only
```

The SDK validates a descriptor:
- strict loader: an unknown key is an error;
- every `implements` entry names a capability in the taxonomy, and a `later`
  capability is refused;
- `consumes` must lie within the capability's in-port carries;
- `produces` must satisfy `MayEmit`;
- every mapped param key must exist in `config`;
- an `output_shape` must be one of the capability's shapes;
- `secret` values are never config: credentials go only through the broker.

**Who declares what, and who trusts it.**

| Field | Declared by | Runtime | Platform |
|---|---|---|---|
| name, version, publisher, presentation | tool | display | display only, rendered as text; icons from a closed set; `docs_url` never fetched |
| implements, consumes, produces | tool | enforced on output | narrows only: capability ∩ catalogue ∩ descriptor; leaving `unverified` needs conformance |
| tier | tool | local ceiling check | a request; the platform assigns |
| permissions, resources, safety | tool | enforced, intersected with local policy | placement (`proxy: ignores` is ineligible in a proxy zone) |
| config | tool | validates every task | validates step settings, renders forms |
| engine version | probed | — | availability and "outdated" |
| selftest, signature | measured by the sensor | gates loading under policy | trust level |

## 5. Tier and trust are platform-assigned (fixes D10)

```
effective_tier(tool, capability, job) = max(
    capability.tier_floor,
    descriptor.tier,                               # can only raise
    T2 if descriptor.safety.side_effects ≠ ∅,      # TC16
    T2 if the job uses out-of-band interaction or custom templates,
    classification(tool@major))
classification default: built-in → the catalogue value;
                        certified → the value in the signed attestation;
                        anything else → T2
```

Trust levels (TC8):

| Level | How it is obtained | Can it run | In published workflows |
|---|---|---|---|
| `builtin` | embedded in the signed sensor binary | yes | yes |
| `certified` | OpenCTEM-signed attestation over the descriptor digest, the artifact digest and the conformance result per `capability@major` | yes | yes |
| `tenant-verified` | the self-test passed on the reporting sensor, and a tenant admin classified the tier (step-up, audited) | yes, sandbox `required` | yes |
| `unverified` (default) | anything else | only with sandbox `required` and an enforcing network backend, as T2 | drafts and admin single checks only |

- Platform-operated (SaaS) sensors load only `builtin` and `certified`
  tools.
- A classification can never go below the capability's floor.
- The effective tier is still bounded by the sensor grant's tier ceiling
  (RFC-052) and the scope authority (RFC-054).

## 6. Runtime protocol additions

Adapter protocol v1 is kept as specified: hello, describe, validate, run,
cancel, log, progress, record, target_status, artifact, heartbeat, verdict
and result. The error classes are kept, and the runtime-only classes cannot
be faked by a tool.

Additions:
- `run.task.capability` (`scan.ports@1`) and `run.task.params`. The runtime
  maps standard params to the tool's own keys through `implements[].params`
  before the tool starts. A value outside the declared subset is refused as
  `invalid_input`, and is never silently dropped.
- `hello` features gain `capability`. An old runtime does not send it.
- `safety.rate_param` is capped by the sensor's local policy. A lowered
  value is logged.
- The runtime stamps provenance into `metadata.properties.provenance`,
  overwriting anything the tool wrote:
  - tool;
  - adapter version;
  - descriptor digest;
  - engine version;
  - content digest;
  - `capability@major`;
  - sandbox status.
- Exec tools: `exit_codes` may map to `partial`. SARIF
  `invocations[].executionSuccessful=false` maps to `partial` with
  `tool_error`.
- The required-output check runs before upload. A miss downgrades the
  result to `partial` with a warning.

## 7. Parsers (TC5, TC6)

**One home: `ctis/importer`.** A parser is a pure function:
- deterministic;
- no network and no filesystem;
- size-, depth- and record-limited;
- fuzzed;
- versioned by its field-mapping spec.

Placement:
- it runs in the tool child (sandbox) through the exec profile, or in a Go
  tool that calls `importer.Parse`;
- the platform parses only pushed and imported files;
- the sensor parsers and the SDK's deprecated `pkg/adapters` are deleted
  after golden parity.

**Named formats in exec:** `output.format` takes any importer format
(`nuclei`, `semgrep`, `trivy`, `betterleaks`, `sarif`, `cyclonedx`, …), so a
wrapped CLI with a known format needs no mapping.

**Declarative mapping for any JSON/JSONL CLI** (`ctis/importer/mapping`,
`apiVersion: openctem.io/mapping/v1`).

- ctis has no external dependencies, so the canonical mapping file is JSON.
  The SDK also accepts YAML and converts it to the same document. The
  descriptor digest covers the mapping (`mapping_digest`).
- The language is closed:
  - paths;
  - `const` and `template` (named vars only), `default`;
  - `lower`, `upper`, `trim`;
  - `as` (integer, boolean, string);
  - `map` (an enum table);
  - `join`, `split`, `max_bytes`, `first`;
  - predicates `exists`, `equals`, `in` and `matches` (RE2, length-capped).
- It is not jq, CEL, a template engine or code.
- The output is plain CTIS, and every emitter and platform check still
  applies.
- Hostile input is bounded:
  - JSON depth ≤ 64;
  - record ≤ 1 MiB;
  - capped strings;
  - range-checked numbers;
  - control characters stripped.
- CEL in mappings is deferred until three real mappings cannot be expressed.

Preferred formats for third-party tools, in order:
1. SARIF (code tools);
2. JSONL with a mapping;
3. CTIS or `jsonl-ctis`;
4. the adapter protocol, only when per-target status, progress or artifacts
   are needed.

## 8. CTIS 1.5 (additive, receiver first; TC10)

- `finding.attack[]`: ATT&CK technique ids the finding enables, checked
  against the id pattern.
- `report.metadata.capability`: `capability@major`.
- Typed `technologies[{name, version, cpe, confidence}]` on service and HTTP
  assets.
- An optional typed `relationships[{type, from_ref, to_ref}]`:
  - the type comes from the closed platform enum;
  - the platform uses it only when both ends are in the report and the type
    is allowed for the capability;
  - when it is absent, derivation by capability still works.
- The `finding.evidence` cap (64 KiB) is documented.

The platform accepts the new members before any sensor sends them. Attack
paths stay platform-derived; a tool never emits them.

## 9. Flow end to end

```
tool.yaml (+ mapping, fixtures)           ← the only place tool facts are written
  │ sensor loads: strict schema, implements ⊆ ctis/capability, selftest, signature (catalogue mode)
  ▼
sensor manifest (RFC-033): tools[].descriptor {digest, full document once} + measured {engine_version, selftest, signature}
  │ heartbeat carries the manifest digest only
  ▼
platform: tool_descriptors (tenant_id, digest) cache  +  tools overlay (enablement, classification, trust, tenant preference)
  ▼
workflow builder: nodes = capabilities; params form = capability params (+ descriptor extras on pinned nodes)
  ▼
plan / dispatch: candidates = implements capability@major ∧ enabled ∧ trust ok ∧ supports the param values ∧ available
  gate: scope authority (RFC-054) ∩ effective tier ≤ grant tier ceiling (RFC-052) ∩ sensor local policy
  task: capability + standard params mapped by the descriptor; batch per descriptor.input
  ▼
sensor runtime: admission → broker → sandbox → adapter/exec → ctis/importer → emitter checks + Check → provenance → outbox
  ▼
platform ingest: CTIS validate → output binding (capability ∩ catalogue ∩ descriptor) → required paths (warn, then quarantine)
  → derivations keyed by capability (ports, relations, finding source) → fingerprint/dedup → inventory and findings
```

## 10. Versioning and compatibility

| Thing | Version | Rule |
|---|---|---|
| Descriptor format | `openctem.io/tool/v1` | Additive keys only; `sdk.min` declares the SDK needed; a breaking format change is `v2` with `openctem tool migrate` |
| Capability | `id@major` | A minor adds an optional param or output path. A **major** changes ports, removes or retypes a param, or adds a required path. Two majors may be served at once; a workflow node pins a major; runs record `capability@major` and the resolved tool and descriptor digest |
| Tool | descriptor `version` (semver) | `openctem tool diff` fails CI when a breaking change lacks a major bump (port or consumes/produces narrowed, required config added, param mapping removed) |
| Engine | probed | `engine.min_version` drives "outdated"; never used for trust |
| Adapter protocol | 1 | Negotiated in hello; features list for additions |
| CTIS | 1.4 → 1.5 | Receiver first |
| Deprecation | `deprecated` on tools and capabilities | The builder refuses new nodes and warns on existing ones; the planner skips the item unless it is pinned; removal after one release train with no sensor reporting it |

**Old sensors (TC12).**
- A sensor that reports no descriptor keeps working through a platform
  fallback: built-in tool name → catalogue capability, with today's tier rule.
- The fallback is removed after one release train.
- The availability view shows "sensor needs update" for such sensors.

## 11. Developer experience

- **No-Go tools.** A `tool.yaml` with `run.profile: exec` around a CLI that
  writes SARIF, CTIS, a named importer format, or JSON/JSONL with a mapping.
- **Go tools.** The `tool.Define(...)` builder gains `.Implements("scan.ports@1")`.
  The SDK owns:
  - scope admission;
  - egress and proxy;
  - sandbox;
  - credentials;
  - retries;
  - progress and heartbeat;
  - cancel;
  - logs;
  - batching and upload;
  - CTIS validation;
  - provenance;
  - error classes.
- **Other languages.** Adapter protocol v1 (NDJSON over stdio).
- **Later, each with a trigger:**
  - container image profile (trigger: the container executor backend lands);
  - declarative HTTP connector (trigger: three pure-REST connectors);
  - Python SDK (trigger: the first external Python author).
- **One CLI** (`cmd/openctem`, TC9):
  - `openctem tool init --kind exec-sarif|exec-json|go|python --capability <ref>`;
  - `validate`;
  - `run`;
  - `test [--capability] [--fuzz 30s]`;
  - `diff <old> <new>`;
  - `describe --json`.

  `openctem-conformance` stays as an alias for one minor.
- **Conformance kit** (`pkg/conformance`). The existing checks are kept:
  manifest, handshake, validate, stdout-only protocol, EOF, cancel and
  fixtures. It adds:
  - a descriptor lint;
  - per-capability suites with fixture servers;
  - a scope check: a recording sink fails the test on any connection to a
    target that was not given or derived;
  - parser and mapping fuzzing;
  - a semver diff;
  - CI templates for third parties.

  Passing the suite at a version is what "certified for `capability@major`"
  means.

## 12. Security

| Threat | Control |
|---|---|
| A tool lies about its capability, tier or outputs to get wider access | Capabilities are platform vocabulary; conformance is needed to leave `unverified`; the tier is platform-assigned (§5); output binding = capability ∩ catalogue ∩ descriptor; required paths checked twice |
| A tool reaches out-of-scope hosts | Admission per target; sandbox network class; untrusted tools need an enforcing backend; conformance scope check; scope authority and grants before dispatch; a discovery tool never scans what it finds in the same task (`expands_targets`) |
| A tool steals the sensor key, the outbox or other tasks' secrets | Protected executor paths; one task per process; broker-only credentials |
| Hostile output (parser exploits, floods, injection into the UI) | Parsers in one fuzzed library; size, depth and record caps; control characters stripped; descriptor strings rendered as text; icons from a closed set; `docs_url` never fetched |
| A hostile mapping file | Closed language; RE2 with length caps; no code; covered by the descriptor digest |
| A tool with side effects declared as harmless | Any declared side effect forces T2; an undeclared side effect fails conformance where detectable |
| Supply chain | Embedded descriptors in the signed sensor; certified = a signed attestation over the descriptor and artifact digests; adapter directories not writable by others and no symlinks; SaaS sensors load only builtin and certified tools |
| Cross-tenant leakage of descriptors | `tool_descriptors` is keyed by tenant, and a digest reported by one tenant is never visible to another; built-in descriptors are public |
| Mutual distrust (RFC-040) | The SDK enforces on the sensor; the platform re-checks tier, scope, outputs and provenance; the sensor re-checks jobs and local policy whatever the platform says |
| Secrets in outputs | `RedactSecretFinding` on every field; `secrets.code@1` requires `secret.masked_value`, and conformance asserts the raw value is absent everywhere |

Every implementation PR carries:
- a threat-model note;
- negative tests:
  - a cross-tenant descriptor digest is not visible;
  - an unverified tool cannot be published;
  - a classification below the floor is refused;
  - oversized or hostile input is bounded.

## 13. Decisions (owner, 2026-10-07: all as recommended)

| # | Decision |
|---|---|
| TC1 | The capability carries the phase, tier floor and ATT&CK/D3FEND/CAPEC ids; a tool only implements; the effective tier is platform-assigned |
| TC2 | The taxonomy lives in `ctis/capability` |
| TC3 | Tools declare `implements`, `consumes` and `produces`, never ports |
| TC4 | Built-in descriptors are embedded `tool.yaml` files |
| TC5 | Parsers live only in `ctis/importer` and run in the tool child |
| TC6 | Zero-code JSON through a closed declarative mapping; CEL later, on evidence |
| TC7 | The full descriptor is sent once by digest in the RFC-033 manifest; the platform caches it per tenant, and an overlay holds the platform-assigned facts |
| TC8 | Trust levels builtin / certified / tenant-verified / unverified; SaaS sensors run builtin and certified only |
| TC9 | One `openctem` CLI with `tool` subcommands; `openctem-conformance` as an alias for one minor |
| TC10 | CTIS 1.5: technique ids, capability on the report, typed technologies, optional typed relationships; attack paths stay platform-derived |
| TC11 | New in v1: `discover.cloud`, `sbom.generate`, `import.file`; later: `config.benchmark`, `discover.repositories`, `check.credentials`, `simulate.attack`; `verify.finding` absorbs the separate validate tool with modes `retest` and `exploit_check` |
| TC12 | Old sensors use a name → capability fallback for one release train, then it is removed |
| TC13 | Required output paths: conformance enforces now; ingest warns per tenant mode, then quarantines after one train |
| TC14 | Rate limiting in v1: the descriptor `rate_param` capped by local policy, plus per-host politeness; a forwarder token bucket later |
| TC15 | Container profile, declarative HTTP connector and Python SDK come later, each with its trigger |
| TC16 | Any declared side effect forces T2 |

## 14. Implementation plan and merge order

| # | Repo | PR | Depends on |
|---|---|---|---|
| CT1 | ctis | `capability` taxonomy package, report checks, generated reference (ctis#36) | — |
| CT2 | ctis | CTIS 1.5 additive members | CT1 |
| CT3 | ctis | `importer/mapping` (mapping v1, loader, engine, limits, fuzz) | — |
| SG1 | sdk-go | Descriptor additions, schema, validator against `ctis/capability`, builder `.Implements()`, full canonical descriptor | CT1 |
| SG2 | sdk-go | Runtime: param mapping, rate cap, provenance, side-effect tier check, required-output check | SG1 |
| SG3 | sdk-go | Manifest reports full descriptors by digest plus measured state; capabilities from `implements`; legacy word list removed | SG1 |
| SG4 | sdk-go | Exec `format: json/jsonl` + mapping; named importer formats | CT3, SG1 |
| SG5 | sdk-go | `openctem tool …` CLI; per-capability suites; scope check; fuzz; diff; CI templates | SG1–SG4 |
| SG6 | sdk-go | Delete `pkg/adapters` and the second SARIF converter; remove the `capabilities` alias | SN1 |
| SN1 | sensor | Embedded `tool.yaml` for all 11 tools with `implements`; input and output fixes; config schemas; delete the word maps | SG1–SG3 on sdk-go `main` |
| SN2 | sensor | nuclei, semgrep, trivy and betterleaks through `ctis/importer`; delete the sensor parsers | SN1 |
| SN3 | sensor | The separate nuclei validate tool → `verify.finding@1` on nuclei | SN1, OC2 |
| SN4 | sensor | trivy `sbom.generate@1`; codeql descriptor | SN1 |
| OC1 | api | `stage` loads contracts from `ctis/capability` behind the same functions; `/scans/stages` adds phase and ATT&CK | CT1, the workflow tool-selection PR |
| OC2 | api | `tool_descriptors` per tenant; param, batch and step-setting maps → descriptor lookups, with the one-train fallback | OC1, SG3 |
| OC3 | api | Tier classification and trust overlay; `CommandTier` per §5; publish gate for unverified tools | OC2, the tools API consolidation |
| OC4 | api | Ingest: capability carries, required paths (warn → quarantine), derivations keyed by capability, CTIS 1.5 members | CT2, OC1 |
| OC5 | api | Drop the legacy vocabulary: `capabilities` table, legacy `tools` columns, `Legacy` words; add the codeql row | OC2–OC4 |
| OC6 | web | Builder palette and forms from capabilities × descriptors; trust, tier and availability badges | OC2 |
| DOC1 | api docs | This RFC, the index row, [tool-contract.md](../architecture/tool-contract.md) | — |
| DOC2 | docs | "Write a tool in 30 minutes" and generated references | SG5 |

The sensor pins only sdk-go and ctis commits that are on `main`, so a sensor
PR stays a draft until the SDK and ctis PRs it needs are merged.
