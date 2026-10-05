# Global catalog trust: who may write shared data

OpenCTEM keeps a few catalogs that **every tenant reads**: the CVE catalog
(`vulnerabilities`), the component catalog (`components`), and the license
dictionary (`licenses`). Each tenant's findings and dependencies point into
them. A value written there is shown to, filtered on and prioritized by every
organization on the platform.

That makes the writer of each shared field a security decision. A tenant's own
sensors, SBOM uploads and administrators are trusted for that tenant's data
only. If tenant input can set a shared field, one tenant decides what all the
others see. A hostile or compromised sensor, or just a buggy one, could:
- hide a critical CVE from everyone's "critical" filter;
- mark CVEs exploited or KEV-listed;
- attach a copyleft license to a popular package in every tenant's license
  report.

## The rule

> Shared catalog fields are written only by trusted sources. A tenant's
> observation is stored on that tenant's own rows, and that tenant's views read
> it from there. Tenant input can **create** a catalog entry for something
> nobody has reported yet. It can never **change** an existing one.

| Data | Trusted writer | Tenant input may | Tenant observation lives on |
|---|---|---|---|
| CVE identity (`cve_id`) | — | create the row | — |
| CVE title, description, CVSS, severity, references, versions, dates | first report (CISA KEV name and description take precedence) | set them only when it creates the row | `findings.title`, `findings.severity`, `findings.cvss_score` |
| `epss_score`, `epss_percentile` | EPSS feed (`epss_scores`) | nothing | `findings.epss_score` (also from the feed, via enrichment) |
| `cisa_kev_*` | CISA KEV feed (`kev_catalog`) | nothing | `findings.is_in_kev` (also from the feed) |
| `exploit_available`, `exploit_maturity` | CISA KEV feed (KEV means exploited) | nothing | `findings.exploit_available` (read by the list filter, the CVE groups and the tenant CVE views through one predicate, `vulnerability.FindingExploitAvailableSQL`) |
| Component identity (`purl`, name, version, ecosystem) | — | create the row | — |
| Component description, homepage, metadata | first report | set them only when it creates the row | — |
| Component licenses | none today (`component_licenses` is not written or read) | nothing | `asset_components.license` |
| License dictionary (`licenses`) | the platform seed | add an unknown id (category and risk `unknown`) | — |

### How it is enforced

- **CVE ingest** (`VulnerabilityRepository.UpsertBatchByCVE`, which also backs
  `UpsertByCVE`): `INSERT ... ON CONFLICT (cve_id) DO NOTHING`. The risk
  columns are taken from `LEFT JOIN epss_scores / kev_catalog`, never from the
  report. The row ids of existing CVEs are read back separately. The old
  fill-blanks merge and the OR on `exploit_available` are gone.
- **Feed propagation**: after every EPSS or KEV sync,
  `ThreatIntelRepository.PropagateToVulnerabilityCatalog` copies the feeds onto
  the catalog. Only rows that differ are written. A CVE that CISA removed
  from KEV is pruned from `kev_catalog` by the next sync (at most 25 removals
  and 2 % of the catalog per sync; a larger drop is treated as a bad feed and
  skipped), and the propagation then clears its KEV columns and
  `exploit_available`. The findings reconciliation clears `is_in_kev` and
  `kev_due_date` on its findings, on every status; severity is not lowered.
- **Tenant API**: `POST /api/v1/vulnerabilities` and
  `PUT/DELETE /api/v1/vulnerabilities/{id}` answer **403** for every tenant
  role. An organization's admin used to be able to edit or delete a CVE that
  every other organization's findings point to. A platform-operator editor, if
  one is ever needed, belongs under the admin realm (`/api/v1/admin`).
- **Components** (`ComponentRepository.Upsert`): `ON CONFLICT (purl) DO
  NOTHING`. Previously the last writer overwrote description and homepage,
  and metadata was merged.
- **Licenses**: ingest and SBOM import call `EnsureLicenses`, which validates
  the ids and adds unknown ones to the dictionary without changing existing
  entries. The tenant's licenses are then stored on its own `asset_components`
  row (`AssetDependency.SetLicense`). A re-scan that declares no license keeps
  the recorded one.

### Tenant views read the tenant's observation first

The descriptive fields of a CVE come from whichever tenant reported it first,
so they must not decide what another tenant's view shows:

- **Active CVEs list and stats** (`ListActiveCVEsByTenant`,
  `GetActiveCVEStats`) and a component's vulnerability list:
  - severity is the worst severity among *this tenant's* findings for the CVE;
  - CVSS and EPSS prefer this tenant's findings, then the catalog;
  - KEV is the finding's `is_in_kev` or the catalog's feed-written KEV columns;
  - exploit availability is the feed-written catalog flag or this tenant's own
    scanner verdict.
- **Findings grouped by CVE** and **related CVEs** use the finding's severity
  before the catalog's. Before this change `COALESCE(v.severity, f.severity)`
  always picked the catalog, because `v.severity` is never NULL.
- **Dashboard average CVSS** uses `COALESCE(f.cvss_score, v.cvss_score)`.
- **License reports** (`GetLicenseStats`, the license-risk breakdown) read
  `asset_components.license`.

Display-only fields (a CVE's title in a list, a component's description) still
come from the catalog. The first reporter can choose them for a CVE or
component nobody had seen, but they no longer change any number, filter, sort
order or flag a tenant acts on.

## Other platform-wide data tenants must not change

A sweep of every tenant-reachable write route for rows shared by all tenants
(tables without `tenant_id`, and system rows of tables with a nullable one)
found these, now closed:

| Data | Was | Now |
|---|---|---|
| Threat-intel feed sync (`threat_intel_sync_status`, `epss_scores`, `kev_catalog`) | `POST /threat-intel/sync` and `PATCH /threat-intel/sync/{source}` let any organization's admin run the sync or switch EPSS/KEV off for everyone | 403 for tenants; the platform administrator uses `GET/POST /api/v1/admin/threat-intel/sync` and `PATCH /api/v1/admin/threat-intel/sync/{source}` (ops_admin+, audited `threat_intel.sync` / `threat_intel.sync_toggle`) |
| System pipeline templates (`pipeline_templates.is_system_template`, e.g. Quick Scan) | readable by every tenant (so it can clone them), but `DELETE /pipelines/{id}` and the step add/update/delete routes did not check `is_system_template`: a tenant could edit the Quick Scan step or delete the template, cascading to every tenant's runs of it | 403 (`getWritableTemplate`); clone it to change it |
| Other tenants' pipelines on tool deactivation | deactivating or deleting a tenant's custom tool deactivated every active pipeline, in any tenant, with a step using a tool of that name (names are unique per tenant, so a custom tool named `nuclei` hit everyone) | only the tool's own tenant's pipelines (`FindPipelineIDsByToolName` is tenant-scoped) |

Left as is, by decision: `pentest_finding_templates.usage_count` is bumped
when any tenant uses a system template. It is a shared popularity counter, not
something another tenant relies on; no content of the template changes.

Guarded already (checked, unchanged): the CVE catalog (above), components and
licenses (insert-only), platform tools/categories/capabilities, system roles
and permission sets, system pentest templates, scan profiles, the settings
row of the caller's own tenant, and catalogs with no tenant write route at all
(asset types, finding sources, compliance frameworks, modules, permissions,
event types, CTEM ids; target mappings are admin-only).

## Migration 000233

Data already written by tenants is corrected once:

1. The risk columns of every CVE (EPSS, KEV, `exploit_available`,
   `exploit_maturity`) are cleared and rebuilt from `epss_scores` and
   `kev_catalog`.
2. Existing `component_licenses` links are copied onto each tenant's
   `asset_components.license` where it is empty, so license reports do not go
   blank. Existing links cannot be traced to the tenant that declared them, so
   every tenant keeps exactly what it saw before. New scans record only their
   own licenses. `component_licenses` itself is left in place and is no longer
   read.

The down migration does not restore the cleared risk values: they were written
by tenant input into a catalog every tenant shares, which is the defect being
fixed.

## What users notice

- On a deployment where the EPSS or KEV sync is off, the catalog's EPSS, KEV
  and exploit flags stay empty. A tenant still sees its own findings' EPSS, KEV
  and scanner-reported exploit flag.
- A scanner-reported "exploit available" now counts only for the tenant whose
  scanner reported it.
- An organization can no longer create, edit or delete CVE catalog entries
  through the API (403).
- A component's description and homepage keep the first value reported.
