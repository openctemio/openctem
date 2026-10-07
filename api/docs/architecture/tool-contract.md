# Tool contract: capabilities, descriptors and outputs

> Last updated: 2026-10-07. Design: [RFC-055](../rfcs/RFC-055-tool-contract-v1.md).
> Related: [scan-stages.md](scan-stages.md) (catalogue, planner, output
> binding), [sensors.md](sensors.md) (manifest, tool contracts),
> [tool-availability.md](tool-availability.md), [sensor-platform-trust.md](sensor-platform-trust.md).

**Question it answers:** how does a scan tool tell the platform what it does,
what it takes and what it produces, and how does the platform decide whether
to trust it?

## 1. The pieces and who owns them

| Piece | Where | Owner | Trusted for |
|---|---|---|---|
| Capability taxonomy | `github.com/openctemio/ctis/capability` (`taxonomy.json`, embedded) | platform vocabulary, code-reviewed | phase, CTEM stage, tier floor, ports, standard params, required output, ATT&CK/D3FEND/CAPEC |
| Tool descriptor | `tool.yaml` (`openctem.io/tool/v1`) next to the tool; built-ins embedded in the sensor | the tool author | narrowing only: what the tool implements, consumes and produces; its config schema, batch shape, permissions, safety |
| Measured state | sensor manifest (RFC-033) | the sensor runtime | engine version, self-test result, signature verification |
| Platform overlay | `tools` and the tenant's descriptor cache | the platform and tenant admins | enablement, tier classification, trust level, preference order |
| Parsers | `github.com/openctemio/ctis/importer` (+ `importer/mapping`) | ctis | the only code that turns tool output into CTIS |

## 2. Capabilities

A capability is an act (`scan.ports@1`), not a tool. Each entry of the
taxonomy has:
- an id and a major;
- a status (`routed`, `planned`, `later`);
- a phase (`discover.passive`, `discover.active`, `assess`, `validate`,
  `collect`), which maps to the CTEM stage (`discovery` or `validation`);
- a tier floor (0 passive, 1 active, 2 intrusive);
- input and output ports from the closed port-type set;
- optional extra outputs (`asset:certificate`, `dependency`);
- the allowed finding types;
- standard params;
- required-output rules;
- framework references.

**Ports carry CTIS asset types.** For example, `url` carries `http_service`,
`discovered_url`, `website`, `api` and `web_application`. A tool may emit:
- what its capability's output ports carry;
- what its input ports carry (re-observed targets);
- the extra outputs;
- findings of an allowed type, when there is a finding output.

`Capability.MayEmit(kind)` answers this.

**Required output** is a list of rules
(`{shape?, select, paths?, any_of?}`):
- `select` picks records (`assets[type=open_port]`, `findings`,
  `findings[type=secret]`, `dependencies`);
- every picked record must carry every `paths` entry and one `any_of` entry;
- `[]` in a path means a non-empty list whose elements all carry the rest of
  the path;
- an empty result is valid;
- named shapes let a capability accept alternatives (`scan.ports`:
  `open_port_assets` or `ip_ports`).

`Capability.Check(report)` returns bounded `not_allowed`, `missing_path` and
`missing_any_of` violations.

The platform keeps only platform-only data in `pkg/domain/stage`:
- default implementations;
- fan-out caps;
- the mapping of CTIS asset types to stored asset pairs;
- the adapter table.

The contracts come from the taxonomy.

## 3. The descriptor

`tool.yaml` declares:
- identity (`name`, adapter `version`, `publisher`, `license`, `engine`,
  `presentation`);
- `class`;
- a requested `tier`;
- `implements` (each with its param mapping, the subset of values supported
  and an optional `output_shape`);
- `consumes` and `produces`;
- `input` (batch shape);
- `config` (JSON Schema subset);
- `permissions` (network class, proxy behaviour, filesystem, credentials,
  capabilities);
- `resources`;
- `safety` (`rate_param`, `side_effects`, `expands_targets`);
- `features` (retest, cancel, streaming);
- `run` (adapter or exec profile, argv, output format, mapping);
- `selftest`;
- `protocol` and `sdk` minimums;
- `deprecated`;
- `artifact` (certified tools only).

Rules the SDK checks when it loads a descriptor:
- strict keys: an unknown key is an error;
- each `implements` entry names a non-`later` capability in the taxonomy;
- `consumes` lies within the in-port carries;
- every `produces` entry passes `MayEmit`;
- every mapped param key exists in `config`;
- `output_shape` is a shape of the capability;
- no secret is ever config.

Tools never declare ports or techniques: they come from the capability.

## 4. Tier and trust

```
effective tier = max(capability floor, descriptor tier, T2 if any side effect,
                     T2 for out-of-band interaction or custom templates, classification)
classification: built-in → catalogue; certified → signed attestation; otherwise T2
```

| Trust | Obtained by | Runs | Published workflows |
|---|---|---|---|
| `builtin` | embedded in the signed sensor | yes | yes |
| `certified` | signed attestation over descriptor digest, artifact digest and conformance per `capability@major` | yes | yes |
| `tenant-verified` | self-test passed + tenant admin classification (step-up, audited) | sandbox `required` | yes |
| `unverified` | default | sandbox `required` on an enforcing backend, as T2 | drafts and admin single checks only |

- Platform-operated sensors load only `builtin` and `certified` tools.
- A classification never goes below the capability floor.
- Dispatch still requires the effective tier to be within the sensor grant's
  tier ceiling (RFC-052), and the target to pass the scope authority
  (RFC-054).

## 5. Run and output path

1. **Plan.** The candidate tools for a capability node are those that:
   - implement `capability@major`;
   - are enabled;
   - have trust that allows the context;
   - support the requested param values;
   - are available on an eligible sensor.

   A tool that is `proxy: ignores` is not eligible in a proxy-only zone.
2. **Task.** The command carries the capability and the standard params. The
   runtime maps the params to the tool's keys through the descriptor, and
   refuses an unsupported value as `invalid_input` before start.
   `safety.rate_param` is capped by the sensor's local policy. Batching
   follows `input.batch`.
3. **Run.** Admission (scope and local policy) → credential broker → sandbox
   → adapter or exec → parser (`ctis/importer`, a named format, or the
   declarative mapping) → emitter checks (CTIS validation, declared types,
   size caps, control characters) → `Capability.Check` (a miss downgrades
   the result to `partial`) → provenance stamp (tool, versions, descriptor
   digest, `capability@major`, sandbox status) → outbox.
4. **Ingest.** CTIS validation → output binding (capability ∩ catalogue ∩
   descriptor `produces`; out-of-contract records are quarantined or warned
   per tenant mode) → required paths (warned, then quarantined after one
   release train) → derivations keyed by capability (open ports and
   `exposes`, DNS relations, finding source), never by tool name →
   fingerprint and dedup.

## 6. Descriptor storage and isolation

- A sensor reports each tool's full descriptor once, by digest, in its
  manifest; the heartbeat carries only the manifest digest.
- The platform caches descriptors per tenant (`tenant_id`, `digest`). A
  digest reported by one tenant's sensor is never visible to another tenant.
- Built-in descriptors are public.
- Descriptor strings are rendered as text only, icons come from a closed
  set, and `docs_url` is never fetched.

## 7. Zero-code tools

Most third-party tools are a directory and need no Go:

```
acme-portscan/
  tool.yaml            # implements scan.ports@1; run.profile exec; output jsonl + mapping
  mapping.json         # openctem.io/mapping/v1 (YAML accepted by the SDK and converted)
  fixtures/task.json
  fixtures/expect.ctis.json
```

The mapping language is closed:
- paths;
- `const`, `template`, `default`;
- `lower`, `upper`, `trim`, `as`, `map`, `join`, `split`, `max_bytes`,
  `first`;
- predicates `exists`, `equals`, `in`, `matches` (RE2, capped).

It has depth, record and string limits, and the descriptor digest covers it.
SARIF tools use `output.format: sarif`. A tool whose format the importer
knows (nuclei, semgrep, trivy, betterleaks, CycloneDX, …) names that format.

`openctem tool init | validate | run | test | diff | describe` scaffolds,
lints, runs offline through the real runtime, and runs the conformance kit:
- per-capability suites;
- the out-of-scope connection check;
- fuzzing;
- the semver diff.

## 8. Old sensors

A sensor that reports no descriptors keeps working for one release train
through the platform fallback: a built-in tool name maps to its catalogue
capability, with the existing tier rule. The availability view marks such
sensors "needs update". The fallback is then removed.
