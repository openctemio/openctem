# RFC-125: Automations: catalog, versions, simulate and the go-live gate

| | |
|---|---|
| Status | Accepted (2026-10-23). In progress: the catalog and the removed types ship first; versions, simulate, preview and validate, the go-live gate and the request actions follow as a stack of pull requests (section 7) |
| Scope | api (`pkg/domain/automation`, `internal/app/automation`, workflow handlers and routes, permissions, migrations), web (automation canvas) |
| Architecture | [automations.md](../architecture/automations.md), [authorization-matrix.md](../architecture/authorization-matrix.md) ("Automation runs act as one person") |
| Related | RFC-046 (scans keep their own schedules), RFC-052 (step-up re-authentication), RFC-111 (approval policy) |

## 1. Summary

An automation is a rule: one trigger, then conditions and actions, run as its
owner. Today a saved rule acts at once, an edit changes a live rule in place,
nothing shows what a rule would do before it acts, and the permission that
edits a rule also switches it on. Several triggers and actions were declared
but never ran. This RFC makes a rule safe to build and to switch on:

1. **One catalog.** The API lists the trigger, action and notification types
   the engine runs. The console builds its palette from that list, and the
   types that never ran are removed.
2. **Versions and a mode.** Publishing creates an immutable version. A live
   rule runs its published version; a rule in simulate runs its draft and
   only records what it would do.
3. **Simulate by construction.** Evaluating a step and executing it are
   separate. A simulated step is never given an outbound client, so it cannot
   change data or send anything. Every run records a per-step trace and a
   ledger of what was sent, or would have been sent, per channel.
4. **Preview and validate** a draft before it runs.
5. **A go-live gate that scales with what the rule can do.** New permissions
   `automations:read`, `automations:write` and `automations:publish`; step-up
   for elevated rules; a second publisher approves high-risk versions.
6. **Rules never close risk on their own.** Rules may request a false
   positive or a risk acceptance; a person always decides, even when the
   organization lets one person decide its own requests. A status action may
   only move a finding to confirmed or in progress, and a run stops after 250
   changes until its owner lets it continue.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Scans keep their own schedules. A sweep schedule for rules (a saved filter evaluated on a schedule, for digests, reports and periodic sweeps) is a later trigger; the old `schedule` trigger, which nothing fired, is removed. |
| D2 | The catalog (`pkg/domain/automation/catalog.go`) is the only list of types. `IsValid` on each type and `GET /api/v1/workflows/catalog` are built from it. |
| D3 | Removed types are not deleted from stored rules: the rule is switched off with `disabled_reason = uses_removed_type`, stays readable, and cannot be switched on until the node is replaced. |
| D4 | Simulate is the mode of every new rule. Rules that were active before versions existed become version 1, live, so working rules do not silently stop. |
| D5 | Simulate is a type split, not a flag: action handlers are executors, and a simulated step goes to an evaluator built without outbound clients. A test proves that no request reaches a fake server in simulate. |
| D6 | Each action has a risk class: low (internal and reversible), elevated (changes a finding's workflow state or leaves the platform), high (starts scans, creates approval requests, or any rule with automation chaining on or a raised change cap). Publish needs `automations:publish`; elevated adds step-up; high adds a second person with `automations:publish` who approves that version's digest. Narrowing (pause, back to simulate) needs no step-up. |
| D7 | `automations:{read,write,publish}` replace `findings:workflows:{read,write}` in one step, without aliases. Roles that could edit and switch on rules keep that power. |
| D8 | A run acts as the rule's owner, checked live per step; a manual run acts as the person who starts it. Preview counts and samples only what the caller may read; the trace counts only runs whose subject the caller may read. |
| D9 | No action writes false positive, accepted, resolved or duplicate. `request_false_positive` and `request_risk_acceptance` create a pending request; an automation is never an approver, and an automation's request waits for a person even when the organization's approval level is `off`. |

## 3. Threat model

| Threat | Control | Test |
|---|---|---|
| A member with edit rights makes a rule act with more power (confused deputy) | runs act as the owner, live permission and scope check per step; publishing needs `automations:publish`; elevated needs step-up; high needs a second publisher who cannot be the publisher | write-only member cannot publish; self-approval refused; editing after approval does not change the approved version |
| A rule closes risk in bulk | request actions only; automation requests never decided by one person; status allow-list | no action reaches a closing status; a request made with level `off` stays pending |
| Simulate that sends or writes | evaluators have no outbound clients; deliveries in simulate are recorded, never sent | a fake server receives zero requests in simulate; finding rows unchanged |
| Preview or trace leaks data outside the caller's scope | preview samples only readable subjects; trace counts only readable subjects | restricted member never counts or sees an out-of-scope finding |
| Mass damage from one run | 250 changes per run, then the run pauses until the owner lets it continue | the 251st change pauses the run |
| Stored credentials in node config | the free-form `http_request` action is removed and its stored headers dropped | migration test |
| Cross-tenant references | every read and write carries the tenant; versions and runs of another tenant answer 404 | cross-tenant negatives |

## 4. Catalog and removed types

Triggers: `manual`, `finding_created`, `finding_status_changed`,
`asset_discovered`, `scan_completed`, `ai_triage_completed`,
`ai_triage_failed`. Actions: `assign_user`, `update_status`, `add_tags`,
`remove_tags`, `create_ticket`, `update_ticket`, `trigger_scan`,
`trigger_ai_triage`, and the request actions of D9. Notifications: `slack`,
`teams`, `email`, `webhook` (registered integrations).

Removed: the `schedule`, `finding_age`, `finding_updated` and `webhook`
triggers; the `assign_team`, `update_priority`, `run_script`, `http_request`
and `trigger_pipeline` actions; the `pagerduty` notification.

## 5. Versions, simulate and the trace

Publishing stores the draft graph as an immutable `automation_versions` row
(definition, digest, risk class, publisher, approver, step-up time). A live
run pins its version; a simulate run runs the draft. Run steps record
in/out counts and per-reason skipped counts; `automation_deliveries` records
what each notification or ticket step sent (live) or would have sent
(simulate), with a redacted payload. Simulate runs are kept 30 days, live
runs and deliveries 180 days.

## 6. Preview and validate

Preview runs the draft against the last N (at most 100) subjects the caller
may read, through the simulate evaluators, and stores nothing. Validate
checks the draft statically: unknown types, graph errors, condition syntax,
missing integrations, permissions the owner lacks, refused status targets.
Both are rate limited per user.

## 7. Delivery

| Step | Pull request | Status |
|---|---|---|
| Catalog, removed types (`automations_removed_types`) | this RFC's first pull request | In review |
| Versions and mode (`automation_versions`) | stacked | In review |
| Simulate engine, trace, deliveries, retention (`automation_run_trace`) | stacked | In review |
| Preview and validate | stacked | Designed |
| Go-live gate and permissions | stacked | Designed |
| Request actions, status allow-list, change cap | stacked | Designed |
| Canvas: simulate/live, preview, validate, trace | stacked | Designed |

Later (not in this RFC's scope): a durable event journal with retries, the
sweep schedule trigger, more triggers from the platform's event catalog,
condition groups, templates, per-channel data ceilings for notifications.
