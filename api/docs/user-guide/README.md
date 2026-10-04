# OpenCTEM User Guide

This is the guide for **people who use OpenCTEM** — security analysts, engineers,
and team owners working in the web app. It explains what every part of the
product does and, step by step, how to do the things you'll actually do.

> Deploying, configuring, or extending the platform? See the
> [operator & developer docs](../README.md) instead.

## The mental model: the CTEM loop

OpenCTEM is organized around **Continuous Threat Exposure Management (CTEM)** — a
repeatable, five-stage loop that never really stops. The left-hand sidebar *is*
that loop, top to bottom, and so is this guide:

```
   ┌─────────────────────────────────────────────────────────────┐
   │                                                               │
   ▼                                                               │
Scoping ──▶ Discovery ──▶ Prioritization ──▶ Validation ──▶ Mobilization
 what's      what's         what actually       is it really      fix it, track
 in scope,   out there      matters most        exploitable?      it, enforce SLAs
 what        (assets,       (rank by real                          
 matters     findings)      risk)                                  
```

You run the loop as **CTEM Cycles** — time-boxed passes with a frozen scope and a
charter — so every round is measurable and each one learns from the last. That's
the single most important workflow in the product; it's covered first, in
[Scoping](03-scoping.md#the-ctem-cycle-start-here).

## Chapters

1. **[Getting Started](01-getting-started.md)** — sign up / log in (password &
   SSO), pick or create a team, accept an invitation, manage your account.
2. **[Team & Access](02-team-and-access.md)** — invite members, roles &
   permissions, data-scope teams, audit log.
3. **[Scoping](03-scoping.md)** — CTEM cycles, scope config, business units,
   crown jewels, asset groups, threat modeling, compliance.
4. **[Discovery](04-discovery.md)** — run scans, connect agents, asset inventory,
   components/SBOM, exposures, credentials, and **findings & triage**.
5. **[Prioritization](05-prioritization.md)** — attack paths, exposure chains,
   business impact, threat intel, and tuning the ranking (priority rules, scoring).
6. **[Validation](06-validation.md)** — penetration testing, attack simulation,
   compensating controls, control testing.
7. **[Mobilization](07-mobilization.md)** — remediation campaigns, ticketing,
   workflows, SLA, exceptions.
8. **[Insights & Reports](08-insights-and-reports.md)** — executive, program
   health, CTEM maturity, and data-quality dashboards; report exports & schedules.
9. **[Settings & Integrations](09-settings-and-integrations.md)** — modules,
   scoring, notifications, and connecting Jira, SCM, SIEM, SSO/SCIM, MCP.

## A few things worth knowing up front

- **Your team is isolated.** Everything you see and do is scoped to the team
  (tenant) you're in. You can belong to several and switch between them.
- **What you can do depends on your role.** Access is *allow-only* — your
  abilities are the sum of your roles' permissions. If a button is missing or
  disabled, you likely lack the permission (or it's owner-only).
- **What you can *see* is a feature of your modules.** If a whole section is
  missing from your sidebar, its module is turned off under
  [Settings → Modules](09-settings-and-integrations.md#modules--turn-features-on-and-off).
- **Assets aren't added by hand.** They're discovered by scans and integrations;
  you enrich them with context (criticality, business unit, crown-jewel status).
- **Sensitive actions require a second pair of eyes.** Marking a finding a false
  positive or accepting its risk goes through an approval request, and verifying a
  fix is a separate permission from triaging it.
