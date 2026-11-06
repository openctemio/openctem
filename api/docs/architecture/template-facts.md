# Template facts: info matches become asset facts

An info match of a template scanner (nuclei) says what a host shows, not what
is wrong with it: the technology it runs, the WAF in front of it, the headers
it does not send, the files it publishes. Such a match is a fact about the
asset. The platform stores it where that kind of fact belongs, and it never
becomes a finding. Matches of severity low and above stay findings.

Code: `pkg/domain/templatefact` (format, validation, classification),
`internal/app/contentrule/template_facts.go` (loading),
`internal/app/ingest/info_facts.go` (routing at ingest),
`internal/app/ingest/info_matches.go` (what is left becomes an exposure).

## The mapping is a content pack

The mapping is a platform content pack of kind `template-facts`
([content-packs.md](content-packs.md)). It is signed with the platform
content key and published on the `stable` channel, like any other platform
pack, so a super admin can publish a new version without a release. The
embedded pack `template-facts-core`
(`internal/app/contentrule/builtin/template-facts-core/facts.yaml`) is
installed on first start. It is also the fallback when no stable pack can
be read. An organization cannot upload this kind.

```yaml
schema: 1
entries:
  - id: tech-detect
    match: {templates: [tech-detect]}       # or template_prefix, tags, metadata
    class: technology
    technology: {name_from: matcher, confidence: 60}
    names:
      nginx: {name: nginx, category: web_server}
      nginxgeneric: {skip: true}               # names no product
  - id: missing-security-headers
    match: {templates: [http-missing-security-headers]}
    class: posture
    posture:
      strict-transport-security: {hsts: false, hsts_include_subdomains: false, hsts_preload: false, hsts_max_age: 0}
      x-frame-options: {frame_options: none}
  - id: robots-endpoints
    match: {templates: [robots-txt-endpoint]}
    class: surface
    surface: {path_from: extracted, source: robots}
```

When more than one entry matches, the first entry of the most specific kind
wins: an exact template id, then the longest id prefix, then tags. A
`metadata` key in the match must be present in the template's metadata.

The linter refuses unknown keys, a confidence of 80 or more, a category
outside the technology categories, a posture key or value that
`http_posture` does not allow, a surface source other than `probe`,
`robots` or `sitemap`, an exposure type that is not an info template type,
and a version pattern that is not RE2 with a `version` group.

## Classes

| Class | Goes to | Notes |
|---|---|---|
| `technology` | the asset's technologies ([asset-technologies.md](asset-technologies.md)) and, with a version or CPE, the software history | WAF, CDN and hosting are technologies of those categories |
| `posture` | the origin's `http_posture` ([web-content-pipeline.md](web-content-pipeline.md)) | header posture is an attribute, never one finding per header |
| `surface` | web surface entries of the origin ([web-surface.md](web-surface.md)) | the matched path (source `probe`) or the paths it extracted (`robots`, `sitemap`) |
| `exposure` | an info exposure ([exposure-taxonomy.md](exposure-taxonomy.md)), optionally of a set type | panels and exposed consoles; the e-mail extractor and the DOM heuristics (no match is discarded) |
| not named, or named but nothing stored | a generic info exposure, counted as `info_unmapped`: a header matcher the posture map lacks, a posture match on an asset that is not a web origin, a technology name that is not one token, a surface match with no clean path, or an endpoint past the per-report cap. Only a match whose fact stored content, or that the mapping skips on purpose, leaves the findings | a new template, kept visible until someone maps it; ingest never drops |

## At ingest

1. Before anything is stored, `applyInfoFacts` reads each info finding of a
   template scanner report. It adds the facts its entry proves to the
   report asset the finding names, as a copy of the report, so the asset's
   own admission applies to them: scope, exclusions and the bound job.
   - Technologies become typed technologies of the asset. If the report
     already names the same technology, the report's own entry is kept.
     If that entry has no version, the version from the match fills it.
   - Posture keys are collected per web origin. `sanitizeHTTPPosture` adds
     them for the keys the report's own headers do not decide. The deep
     property merge keeps stored keys the match does not name.
   - Surface entries become report endpoints of the match's own origin.
     They then pass the endpoint plan's target check and its limits. A
     report gets at most 2,000 of them.
2. The stored pipelines then run unchanged. Set reconciliation records the
   technologies as sightings of the template scanner: they never remove
   what the scanner did not report, and they leave after the scan TTL
   (30 days) when no scan sees them again. `recordTechnologies` marks the
   scanner's rows as secondary. `recordSoftware` turns a technology with a
   version into a banner-class reading of the technology history.
3. `routeInfoMatches` takes the fact matches out of the
   findings and counts them in `info_observations` and in `info_facts` on
   the receipt, and on the step run. Exposure and unmapped matches become
   info exposures as before. If the organization files info matches as
   findings (`info_matches_as_findings`), they stay findings, and their
   facts are recorded as well.

## Precedence and history

- **Technologies.** In `asset_technologies`, a secondary detection
  refreshes last seen and fills a source, category, vendor or CPE that is
  still unknown. It never replaces what a fingerprinting probe or a
  detection rule recorded. When sources disagree on the version, the
  collapsed set keeps the higher version, as for every source.
- **Software history.** A template detection is banner class, with a
  confidence below 80 (the linter enforces it). One match can only add a
  candidate version. It becomes established only after three readings over
  12 hours, and it never overrides a stronger class
  ([RFC-066](../rfcs/RFC-066-inventory-vulnerability-matching.md), technology history).
  The inventory matcher builds findings from established versions only.
- **Posture.** A key a template match proves only fills a key the stored
  `http_posture` lacks: a stored reading (the headers a probe such as httpx
  reported) wins across reports, as a probe's technology source does. Other
  producers keep the deep merge, where the newest reading of a key wins. A
  header the report itself carries beats a template match in the same report. `frame_options` and `referrer_policy` take
  `none` for a header that was not sent. A header value is never read as
  `none`.

## Provenance and retention

- Each technology row carries its source and its first and last seen
  times. The software history keeps the sightings, the class and the
  confidence. Each endpoint keeps its sources and its last run and sensor.
- The finding is not stored, so the template id of a fact is not stored
  either. The step run's `info_observations` and `info_facts` counts and
  the receipt record what a run saw.
- Retention follows the store each fact lands in: the scan TTL for
  technologies, the web surface retention for endpoints (gone after 30 days
  without a sighting, purged a year later), and the posture until a later
  reading replaces it.

## Threat model

| Threat | Control |
|---|---|
| A hostile target makes a template report a fake technology or version | names come from the signed mapping, or are one bounded token; a version is a dotted token read from the extracted values (each at most 256 bytes, at most 20), and a value marked sensitive is never read; banner class below 80, so no single match establishes a version, closes a finding or displaces another source |
| Markup or control characters in extracted values or matcher names | token patterns (`[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}`), CPEs only as `cpe:2.3:` text; the console renders them as text |
| Paths of another host injected through robots.txt | only paths of the match's own origin; wildcards, queries, fragments and spaces are refused; the endpoint plan checks the origin against the bound job's targets |
| Personal data in extracted values (emails) | nothing is discarded (owner rule, research/446): the e-mail extractor is an info exposure, and every address in a finding's text, evidence and extracted values is masked (`***@example.com`, `safetext.MaskEmails`) before anything is stored, whatever the path (exposure, `info_matches_as_findings`, out-of-scope asset); no extracted value is stored except as a version or a path |
| A tenant forges matches (a custom template named like a known one) | the facts land only on the tenant's own assets, through the same admission as the report's assets; secondary and below 80, as above |
| A forged mapping pack | platform packs only, signed, linted; organizations cannot upload the kind |
| Cross-tenant | the router works on one report; every store it feeds is tenant-scoped (no new query) |

No route changes. No data changes on deploy: existing info findings move
only through the operator command (`refingerprint -info-exposures`).
