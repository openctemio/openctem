# RFC-092: Tool-agnostic platform — sensors declare tools, the platform orchestrates capabilities

| | |
|---|---|
| Status | Proposed (2026-10-14). P0 in implementation: declared tools join the organization's catalog; capability steps run any tool whose reported contract implements the capability |
| Scope | api (sensor manifest, tool catalog, stage planner, ingest), web (tool lists, scan intensity), ctis (tool descriptor schema, content kinds), sdk-go (descriptor validator, target typing), sensor (descriptors) |
| Related | RFC-055 (tool contract v1; this RFC builds its platform items OC2, OC3 and OC6), RFC-033 (sensor manifest), RFC-038 / research 128 (tool settings), RFC-040 (signed jobs, mutual distrust), RFC-061 (content packs), RFC-046 (stage catalog), RFC-043 (finding identity) |

## 1. Summary

Adding or replacing a scanning tool must not need a platform release. A tool
is described once, in the descriptor (`tool.yaml`) that its sensor already
signs into its manifest (RFC-055): the capabilities it implements, the
targets it takes, its settings schema, its display text, its safety facts and
the content it reads. The platform takes the tool in from that declaration,
orchestrates by **capability** (`dast.web@1`, `sast.code@1`, `scan.ports@1`),
treats a tool as an optional preference, and receives results as CTIS. The
only platform change a new kind of scanning needs is a new **capability**:
an entry of the ctis capability taxonomy.

## 2. Problem (measured 2026-10-14)

- A tool the platform's seeded `tools` table does not list is dropped from a
  sensor's manifest (`unknown-tool`), so a new tool is invisible until a
  migration seeds it.
- The stage catalog lists the tools of each capability in code; parameter
  mapping, list input and capability jobs are three more hard-coded tables.
- About 76 branches in api and web name a tool where the tool's descriptor
  already carries the fact; about 15 parse a tool's raw output where a ctis
  importer should; about 26 are capability behaviours keyed by a tool name.
- A toy `dast.web@1` tool built on sdk-go and installed on the released
  sensor through an adapter directory showed that everything else (settings
  form, tier and trust, grant, claim, sandbox, CTIS ingest, technique) already
  works from the manifest.

## 3. Design

### 3.1 Declared tools join the organization's catalog

When a sensor of an organization registers a manifest, each tool with a valid
contract whose descriptor hashes to its digest is **declared**: the
organization's tool catalog gets a row projected from the descriptor
(`tools`, tenant row, `metadata.origin = sensor_manifest`) with its name,
display name, description, capability keys, target types, settings schema and
version. A newer version refreshes the row; an older one does not.

- The row never takes the name of a platform tool and never overwrites a tool
  a member created.
- Its text is bounded, stripped of control and format characters and rendered
  as text; a declared tool's documentation link is not taken in.
- An organization holds at most 128 declared tools.
- A platform sensor (no organization) declares nothing.
- The row is edited only through the sensor (editing and deleting it are
  refused); the organization may deactivate it.
- A tool without a contract still needs a catalog row (sensors older than the
  tool contract).

### 3.2 Capability-first planning

A workflow step names a capability and optionally a tool. The tools that can
run it are those whose **reported contract** implements the capability, read
from the organization's current sensor manifests. The parameter mapping (the
capability's standard parameters to the tool's settings keys), list input and
capability jobs come from the same contracts. The order in which candidates
are tried: the step's pin, the step's preferred tools, then the platform's
default preference for the capability, then the other implementations.

### 3.3 Policy is unchanged and not negotiable by a manifest

The tier is the highest of the capability's floor, the descriptor's tier, T2
for any declared side effect and T2 for a tool the platform does not trust
(RFC-055 §5). The sensor's grant ceiling, the scope (RFC-054), the scan
intensity (RFC-071) and the sensor-local policy apply to a declared tool as to
any other. A descriptor naming an unknown capability is refused at sanitize.

### 3.4 Results

The tool emits CTIS, or its descriptor names a ctis importer format; the
platform never parses a tool's raw output. The technique of a finding comes
from the capability the report was produced for.

### 3.5 Content kinds

Content consumed by tools is typed by a **content kind** that names a format
dialect (`nuclei-templates`, `semgrep-rules`, `trivy-db`), registered in
ctis with its validator. A tool declares the kinds it reads in its
descriptor's `content[]` slots; the platform offers a kind when a manifest of
the organization declares it. Scanner-template types and quotas become keyed
by kind. Storage and delivery are RFC-061.

### 3.6 A new capability

1. ctis: add the capability to the taxonomy and release.
2. api: take the ctis release; add the capability's technique if it reports
   findings; add a port or asset type only if it produces a new kind of
   thing.
3. web: the capability's display name in en and vi.

## 4. Threat model

| Threat | Control |
|---|---|
| A hostile sensor declares a tool to show misleading text or links | Text bounded and sanitized, rendered as text; no documentation link from a declaration; icon and category limited to short words |
| A sensor floods the catalog | At most 128 declared tools per organization; descriptor and manifest size bounds (RFC-033) |
| A declaration shadows a platform tool or a member's tool | Never takes a platform tool's name; never overwrites a member's row; name lookups read the platform tool first |
| Cross-organization leak | The row's organization is the sensor's, from its key; every read is organization-scoped |
| A manifest grants its tool power | Nothing in the projection grants: tier, trust, grant, scope, intensity and local policy decide |
| Deleting a declared tool to hide it | Refused (the next manifest restores it); deactivation is the organization's audited switch |

## 5. Decisions needed

1. **Trust of a tool the platform did not build** (today a name list): a
   signed descriptor attestation per release, plus an organization
   administrator's classification for its own tools (RFC-055 TC8).
2. **Which engine is a capability's default**: a descriptor hint set by the
   sensor release, overridable per organization, replacing the platform's
   preference list.
3. **Template quotas and usage keyed by content kind**: the API's per-tool
   fields become maps (a breaking API change).

## 6. Phases

| Phase | Content | Exit criterion |
|---|---|---|
| P0 | Declared tools (§3.1); capability candidates, parameter mapping, list input and capability jobs from reported contracts (§3.2); web tool lists and scan intensity from the API | A new tool added to a sensor appears with its settings form, runs in a scan by capability and its findings are ingested, with no platform change |
| P1 | ctis descriptor schema and validator (with localized display strings, the default hint, scope and low-impact facts); trust classification; step settings validated by the descriptor schema; scope gates from descriptor facts; `verify.finding@1` for validation and retest; content kinds; ingest derivations keyed by capability; importer moves | Tool-named branches in api and web reduced to tracked exceptions |
| P2 | Takeover as a capability; rule namespaces from importers; budgets from descriptors and history; import formats served by the API | Tool names in api and web code only as capabilities, content kinds and docs |
