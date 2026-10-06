# Discovery

**CTEM Stage 2.** Now that scope is defined, discovery finds what's actually out
there — your assets, their software components, and the exposures on them. This is
driven by **scans** (run by **agents**), and it produces **findings**. These pages
live under the **Discovery** sidebar section (scan/agent setup lives under
**Settings → Scanning**).

## Run a scan

**Discovery → Scans** (`/scans`) manages scan configurations and their runs, split
across two tabs: **Configurations** and **Runs**.

**Quick Scan** (fastest) — click **Quick Scan**, paste your **Targets**, pick a
**Scanner**, and **Start Scan**.

**New Scan** (full control) — click **New Scan** to open a 4-step wizard:

1. **Basic Info** — name, scan type, a predefined workflow/profile, scan mode, and
   agent preference.
2. **Targets** — what to scan.
3. **Options** — scanner options.
4. **Schedule** — run now (**Start Scan**) or later (**Schedule Scan**).

On the **Runs** tab, filter by status (running/completed/failed), search, and
export. Open a run to watch its progress and click **View {n} Findings** to jump
straight to what it found. A configuration's row menu lets you **Trigger Scan**,
Edit, Clone, Pause/Activate, or Delete it.

> There's no per-run *Stop* or *Retry* — an in-flight run can be **Cancelled**,
> and configurations can be **Deleted** (Danger Zone on the scan detail page).

## Connect an agent

Scans are executed by **agents** — a daemon agent runs continuously wherever you
deploy it; a CI/CD runner executes in a pipeline. Manage them at **Settings →
Scanning → Agents** (`/agents`).

1. Click **Add Agent**.
2. Choose the **Agent Type**, give it a **Name**, and pick an **Execution Mode**,
   then continue.
3. The platform generates an **API Key** — copy it and configure your agent with
   it, then **Done**.

You can regenerate an agent's key later. CI/CD pipelines are not sensors:
they authenticate with their CI provider's OIDC identity and are listed under
CI/CD (`/ci-runners`; the old `/runners` URL redirects there). Scan behavior is further shaped by **Profiles**, **Tools**,
and **Scanner Templates** (also under Settings → Scanning).

## Asset inventory

Discovery populates your inventory automatically — **assets are ingested from
scans and integrations, not added by hand**.

- **Discovery → Asset Inventory** (`/assets`) is the overview: headline metrics
  and category cards. On first run you'll see CTAs to **Run Discovery Scan**,
  **Connect Provider**, or **Configure Scope**.
- **All Assets** (`/assets/all`) is the unified, filterable table — search,
  faceted filters, and CTEM filter chips. Select rows to reveal bulk actions:
  **Assign owner**, **Set criticality** (pick a level → **Apply**), and **Add
  tag**. (These need the *assets:write* permission.)
- Clicking an asset opens its **detail** view — criticality, risk score,
  exposure, and its findings. (The detail page is read-through; you set
  criticality in bulk from the table, and business context in
  [Scoping](03-scoping.md#tell-the-platform-what-matters).)

If the duplicate correlator flags possible merges, the inventory shows a
**Review** card linking to the duplicates view.

## Software components (SBOM)

**Discovery → Components** (`/components`) is your software bill of materials —
libraries and packages discovered across your assets, with their vulnerabilities,
license risks, and outdated versions. Use **All** for a filterable table (direct
vs transitive, ecosystem, vulnerable) and **Export SBOM** for the standard format.

## Exposures

**Discovery → Exposures** (`/exposures`) is the categorized view of what's wrong,
split into **Vulnerabilities**, **Secrets**, **Code**, and **Misconfigurations**.
Each is a lens onto the same underlying findings, grouped by exposure type so the
right team can work its own queue.

## Credentials

**Discovery → Credentials** (`/credentials`) surfaces leaked or exposed
credentials and the identities they belong to. Because this is sensitive, viewing
plaintext is audited.

## Findings & triage

Findings are the core unit of work discovery produces. Open the list from
**Insights → Findings** (`/findings`) or from any scan run.

**Working the list:**

- Tabs: **All Findings / Groups / Pending** (approvals). Severity sub-tabs
  (**All / Critical / High / Medium / Low**) with counts, plus a search box and a
  full **status** filter (New, Confirmed, In Progress, Fix Applied, Resolved,
  False Positive, Accepted, In Review, Verified, …).
- A row's menu: **View Details**, **Assign**, **Change Status**, **Create Jira
  Ticket** (if ticketing is configured), **Add to remediation**, **Mark as False
  Positive**, or **Delete**.
- Select rows for **bulk actions**: **Assign to…**, **Create remediation task**,
  or **Change Status** (bulk status is limited to Confirmed / In Progress /
  Resolved — see approvals below).

**Working a single finding** (`/findings/{id}`):

- Change **Status**, **Severity**, or **Assignee** from the header.
- **AI Triage** proposes an assessment; **Re-verify** re-runs the CTEM stage-4
  safety check; **Request Verification Scan** kicks off a targeted re-scan (enter
  a scanner name like `trivy`, `semgrep`, `nuclei`).
- On the **Evidence** tab, **Add Evidence** (type, description, URL). The
  **Activity** tab holds comments; **Remediation** and **Related** show linked
  work and related findings.

**Approvals (separation of duties):** some status changes — marking a finding
**False Positive** or **Accepted (Risk)** — can't be done unilaterally. They open
a **Request Status Approval** dialog where you enter a justification. The request
then goes to **Insights → Findings → Pending** / the **Approvals** page
(`/findings/approvals`), where an authorized reviewer can **Approve** or **Reject**
(with a reason). This is why those statuses are excluded from bulk changes, and
why *verifying* a fix is a separate permission from triaging it.
