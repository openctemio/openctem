# Insights & Reports

The **Insights** section turns everything the platform tracks into dashboards for
different audiences, and **Reports** is where you export and schedule summaries.
These are read-through views — you look, filter, and export, rather than change
data here.

## Insights dashboards

All of these live under the **Insights** sidebar section. Each reads live data;
the only in-page control is usually a time-period toggle.

| Dashboard | Route | What it answers |
|-----------|-------|-----------------|
| **Executive Summary** | `/insights/executive` | Risk score, findings resolved, MTTR and other headline numbers for leadership. Toggle the period (7/30/… days). |
| **Program Health** | `/insights/program-health` | Whether the CTEM program itself is healthy — coverage, MTTR, data quality, risk trend, validation coverage. |
| **CTEM Maturity** | `/insights/ctem-maturity` | A weighted maturity score with per-stage coverage and trend. |
| **Data Quality** | `/insights/data-quality` | How complete and trustworthy your asset/finding data is. |

Some dashboards are permission-gated — if you don't have access you'll see a
"You don't have access…" message rather than the metrics. If a section belongs to
a module your team hasn't enabled, you'll see "Module not enabled".

The **Findings** entry under Insights opens the main [findings list](04-discovery.md#findings),
and **Reports** opens the reports hub below.

## Reports

**Reports** (`/reports`, titled "Security Reports") gives you two things, both
backed by live data:

- **Executive summary export** — download the executive summary as a CSV.
- **Scheduled reports** — set up recurring digests that are **emailed** to
  recipients on a schedule you choose.

> There is no on-demand "report library" of saved PDF artifacts — the platform
> doesn't store generated report files. Think of Reports as *export now* +
> *schedule recurring emails*. For a formatted engagement deliverable, use the
> **Pentest → Reports** section under [Validation](06-validation.md#penetration-testing).
