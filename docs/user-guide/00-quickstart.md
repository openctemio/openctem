# Quick Start: from zero to your first remediated finding

This tutorial threads the whole product into one path — the fastest route from a
brand-new team to a vulnerability that's been found, prioritized, and fixed. Each
step links to the chapter with the full detail. Follow it once and the rest of the
guide will make sense.

> **Prerequisites:** you can sign in and you're an **owner** or **admin** of a
> team (so you can configure scope and connect an agent). See
> [Getting Started](01-getting-started.md) if you're not there yet.

## 1. Define what to look at (Scoping)

1. Go to **Scoping → Scope Config** and **Add Target** for something you're
   allowed to scan (a domain, an IP range, a repo).
2. *(Optional but recommended)* Mark your most important asset as a
   [Crown Jewel](03-scoping.md#tell-the-platform-what-matters) and set up a
   [Business Unit](03-scoping.md#tell-the-platform-what-matters) — this is what
   makes prioritization meaningful later.

→ Full detail: [Scoping](03-scoping.md).

## 2. Connect an agent (Discovery setup)

Scans run on an agent. To get one:

1. **Settings → Scanning → Agents → Add Agent**.
2. Choose the type and mode, name it, and copy the generated **API Key**.
3. Deploy the agent with that key (see the [agent deployment docs](../README.md)).
   It will connect back and appear online.

→ Full detail: [Discovery → Connect an agent](04-discovery.md#connect-an-agent).

## 3. Run your first scan (Discovery)

- Fastest: **Discovery → Scans → Quick Scan**, paste a target, pick a scanner,
  **Start Scan**.
- On the **Runs** tab, watch it progress, then click **View {n} Findings**.

→ Full detail: [Discovery → Run a scan](04-discovery.md#run-a-scan).

## 4. See what matters most (Prioritization)

Open **Insights → Findings**. The list is already ranked by risk. Use the
**Critical / High** severity tabs, and check **Prioritization → Attack Paths** to
see which findings sit on a real path to a crown jewel. Those are what you work
first.

→ Full detail: [Prioritization](05-prioritization.md).

## 5. Confirm and assign (Triage)

Open a finding:

1. Set its **Status** (e.g. Confirmed) and pick an **Assignee**.
2. Add context on the **Evidence** tab, or run **AI Triage** for a suggested
   assessment.
3. If it's a false positive or accepted risk, use **Request Status Approval** —
   a reviewer confirms it on the [Approvals](04-discovery.md#findings--triage)
   page (this is the separation-of-duties control).

→ Full detail: [Discovery → Findings & triage](04-discovery.md#findings--triage).

## 6. Get it fixed (Mobilization)

1. From the finding (or **Mobilization → Remediation**), create a remediation
   campaign / task.
2. **Create Jira Epic/Ticket** to hand it to engineering (configure
   [Ticketing](09-settings-and-integrations.md#integrations) once, first).
3. Track progress on the campaign; enforce deadlines with an
   [SLA policy](07-mobilization.md#sla-compliance).

→ Full detail: [Mobilization](07-mobilization.md).

## 7. Verify the fix (Validation) and close the loop

When engineering says it's done:

1. On the finding, use **Request Verification Scan** to re-scan, or **Re-verify**
   to re-run the safety check.
2. Once it comes back clean, set the status to **Resolved / Verified**.

You've now completed one pass of the CTEM loop for a single finding. To run this
as a repeatable, measurable program across your whole scope, wrap it in a
[**CTEM Cycle**](03-scoping.md#the-ctem-cycle-start-here) — that's the real way
the platform is meant to be used, and it's the first thing in the
[Scoping](03-scoping.md) chapter.

---

**Where to go next:** the [chapter index](README.md) covers every area in depth.
If a feature is missing from your sidebar, its
[module](09-settings-and-integrations.md#modules--turn-features-on-and-off) is
probably turned off.
