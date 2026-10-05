# Prioritization

**CTEM Stage 3.** Discovery finds far more exposures than any team can fix at
once. Prioritization ranks them by *real* risk — combining severity, exploit
likelihood, reachability, and business value — so you work the few that matter
first. These pages live under the **Prioritization** sidebar section.

Most Prioritization pages are **analysis views**: they read your live data and
rank it. The place you actually *change* how ranking works is **Priority Rules**
and **Risk Scoring** (both under Settings).

## Attack Paths

**Prioritization → Attack Paths** (`/attack-paths`) ranks your assets and public
entry points by how attackable they are, so you can see which exposures sit on a
real path toward something valuable. It's a read-through view — click an asset to
jump to its findings (`/findings?assetId=…`) or into the inventory.

## Exposure Chains

**Prioritization → Exposure Chains** (`/exposure-chains`) shows multi-step chains
that connect an exposure to a high-value target. Use it to understand *why* a
finding is dangerous in context, then click through to the affected assets.

## Business Impact

**Prioritization → Business Impact** (`/business-impact`) aggregates risk by
crown jewels and asset criticality, so leadership can see exposure through a
business lens rather than a raw finding count. It's a summary view — no actions.

## Threat Intel

**Prioritization → Threat Intel** (`/threat-intel`) brings in external signal:
EPSS exploit-probability scores, the CISA **Known Exploited Vulnerabilities**
(KEV) catalog, indicators of compromise, and tracked threat actors.

- **Refresh** re-pulls the latest feed data.
- **CVE Lookup** — type a CVE ID (e.g. `CVE-2021-44228`) and search to enrich it
  with EPSS/KEV context on the spot.

## Trending

**Prioritization → Trending** (`/trending`) shows how your exposure is moving over
time — month-over-month and by severity — so you can tell whether the program is
gaining or losing ground. Read-only.

## Tune how prioritization works

Two settings pages control the ranking itself:

- **Priority Rules** (**Settings → Priority Rules**, `/settings/priority-rules`)
  — create override rules that bump or set the priority class of findings that
  match conditions you define. Click **Create Rule**, choose the target, set the
  evaluation order, add conditions, and save. A rule needs at least one
  condition (a rule without conditions would re-class every finding), and each
  condition must use a known field, an operator that field supports and a value
  of the right type; the API refuses anything else with `422`.
- **Risk Scoring** (**Settings → Risk Scoring**, `/settings/scoring`) — edit the
  weighted components that produce each finding's risk score, using presets or
  custom weights. **Preview** the effect, **Save Changes**, optionally enable the
  **CTEM scoring bonus**, then **Recalculate** to re-score existing findings.

> Changing scoring weights affects every open finding. Preview first, and expect
> to run **Recalculate** after saving for the change to apply to existing data.
