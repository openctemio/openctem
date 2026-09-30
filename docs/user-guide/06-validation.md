# Validation

**CTEM Stage 4.** Before you spend effort remediating, validation asks: is this
exposure *actually* exploitable, and are our defenses *actually* working? These
pages live under the **Validation** sidebar section.

## Penetration Testing

**Validation → Penetration Testing** organizes manual and guided offensive
testing. It's a module (enable it under Settings → Modules) with sub-sections:

- **Campaigns** — scope and track a pentest engagement.
- **Findings** — findings raised during a campaign.
- **Retests** — re-verify that a previously reported issue is fixed.
- **Reports** — the deliverable for an engagement.
- **Templates** — reusable test scaffolds.
- **MITRE Coverage** — which ATT&CK techniques your testing has covered.

Use this when a human tester (internal or third-party) drives the assessment, as
opposed to the automated scanning in [Discovery](04-discovery.md).

## Attack Simulation

**Validation → Attack Simulation** (`/attack-simulation`) lets you **run**
existing simulations against your environment and review the results, to confirm
whether a given exposure can really be exploited.

> Creating a *new* simulation from this page is **not available yet** ("Coming
> soon"). You can list and run the simulations that already exist.

## Compensating Controls

**Validation → Compensating Controls** (`/controls`) tracks the mitigations that
reduce risk when a finding can't be fully fixed (e.g. a WAF rule in front of a
vulnerable service).

- **Add Control** — create a control (name, what it does).
- Edit or delete a control, and **link it to a finding** it mitigates.
- **Record** a test result to log that you verified the control still works.

## Control Testing

**Validation → Control Testing** (`/control-testing`) is where you define and run
tests that prove a security control is effective — for example an "MFA
Enforcement Test".

1. Create a control test: name it, pick a framework/category, and describe the
   test procedure and expected result.
2. Run it and **Record** the result with evidence and notes.

Results roll up into **MITRE ATT&CK coverage** so you can see which techniques
your controls demonstrably defend against.
