# Rule sources

> RFC: [RFC-118](../rfcs/RFC-118-rule-sources.md). Related:
> [content packs](content-packs.md), [placement](placement.md).

A single-scanner scan runs the **platform's rules** (the sensor's managed
template or rule pack), the **organization's own scanner templates**, or
**both** together in one tool run. The setting is called *rule sources*.

| Value | What runs | Custom templates sent | Sensor requirement |
|---|---|---|---|
| `both` (default) | platform + organization | yes, when the scan names any | none (an older sensor runs them in two passes) |
| `platform` | platform only | no (the scan's `custom_template_ids` are ignored for the run) | none |
| `tenant` | organization only | yes (at least one is required) | reports `rule.sources@1` |

## Where it is set

- **Scan profile** (`scan_profiles.rule_sources`, NOT NULL, default `both`):
  `POST/PUT /api/v1/scan-profiles` field `rule_sources`.
- **Scan** (`scans.rule_sources`, NULL = inherit the profile's):
  `POST/PUT /api/v1/scans` field `rule_sources` (`""` on update clears it).
  A scan with `tenant` must name custom templates
  (`scanner_config.custom_template_ids`), or the save is refused
  (`RULE_SOURCES_NO_TEMPLATES`).
- The effective value (the scan's, else its profile's) is part of the
  approval definition (RFC-073), left out when it is `both`, so changing it
  on the scan or on its profile needs a new approval when a rule holds the
  scan.

Effective value of a run: the scan's own, else its profile's, else `both`
(`scannertemplate.EffectiveRuleSources`). A profile that no longer exists
counts as none; a profile that cannot be read refuses the trigger.

## At trigger and dispatch

`internal/app/scan/rule_sources.go`:

1. `applyRuleSourcesAtTrigger` resolves the value before the sensor opt-in
   check and records it in the run context (`rule_sources`; a caller's value
   is discarded). For `platform` the scan's template ids are dropped from the
   in-memory config (the stored scan is unchanged), so neither the opt-in
   check nor the sensor preflight counts templates that will not be sent.
2. `customTemplatesFor` resolves the templates **fail closed**: a template
   that is not in the scan's organization, deleted, malformed or not active
   fails the run (`CUSTOM_TEMPLATES_UNRESOLVED`, with the template names).
3. `withRuleSources` puts `rule_sources` in every command payload; a `tenant`
   command also gets `required_features: ["rule.sources@1"]`, which the claim
   predicates (organization and shared sensors) match against the sensor's
   reported capabilities only. The placement view shows
   `rule_sources_unsupported` for a sensor that lacks it.

Workflow scans are unchanged: their steps run the platform's rules.

## On the sensor (sdk-go and sensor)

- The executor refuses a command that contradicts itself (`platform` with
  templates, `tenant` without, an unknown value) and passes the value to the
  scanner as `ScanOptions.RuleSources`.
- Every custom template is checked after its signature
  (`core.CheckCustomTemplate`); a nuclei template with `code`, `javascript`,
  `flow`, `file`, `headless`, a self-contained request, `workflows`, a
  payload file or a second YAML document fails the command before anything
  is written.
- A scanner that honors the value runs `both` in one invocation (nuclei with
  both template directories; betterleaks with the organization's rules
  extending the defaults; opengrep and semgrep with both configs) and the
  sensor reports `rule.sources@1`.
- Findings of the organization's rules carry `tenant:`-prefixed rule ids.

## Key files

- `api/migrations/003137_scan_rule_sources.*`
- `api/pkg/domain/scannertemplate/rule_sources.go`
- `api/internal/app/scan/rule_sources.go`, `trigger.go`, `zones.go`
- `api/internal/app/command/placement.go` (`missingFeatureReasons`)
- `api/pkg/domain/sensor/reported.go` (`CapabilityRuleSources`)
- sdk-go `pkg/core/rule_sources.go`, `pkg/core/custom_template_check.go`
