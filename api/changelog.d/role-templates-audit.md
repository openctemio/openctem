### Added: three role templates: remediation lead, validation lead and detection engineer

- **Remediation lead** (engineering managers, security champions): everything a remediation owner does, plus the team's remediation tasks (create, split, merge, tracker issue, mark fixed, one exception), assignment within the team and bulk status. Never severity, verify, approve or triage.
- **Validation lead** (pentest and red team leads): a validation engineer who also maintains methodology checklists and attacker profiles and requests engagement scope and authorization letters. Never approves scope or risk.
- **Detection engineer** (detection, SOC and purple team defenders): reads simulations, control tests and observed campaigns, and records compensating controls and their test results. Runs no attack or scan and changes no finding.
- Each is available as a role template and as a team preset.

### Fixed: role templates hold what their people need, and nothing that opens no route

- An audit of every template against the route gates its people use found grants that did not work and work that was missing. New template versions (roles and team presets created from the old version keep their permissions and show "update available"):
  - program lead v3: approves exposure dispositions (`findings:exposures:triage`), approves scan runs (`scans:approve`), manages organization dashboards, shares saved views with the organization;
  - risk approver v2: approves exposure dispositions (`findings:exposures:triage`; alone it changes nothing);
  - remediation owner v2: follows the pentest campaigns they are a client of (`pentest:campaigns:read`, `pentest:findings:read`; campaign membership is still checked on every campaign route);
  - validation engineer v3: runs targeted scans (`scans:write`; a run needs it with `scans:execute`);
  - security analyst v4: drops `scans:execute`, which opened no route without `scans:write`;
  - AppSec engineer v3 and CI integrator v2: `integrations:read`, without which `integrations:scm:read` listed no code host connection; AppSec also reads scope and runs AI triage;
  - vulnerability manager v4: shares saved views with the organization; scan operator v2: browses the content catalog; auditor v2: reads simulations, control tests and automations.
- The generated authorization reference now includes the 33 campaign routes registered in a nested route group (it listed only routes on a router named `r` or `router`).
- New tests in `internal/authzdoc` check that every template permission opens a route the template passes, and that each template passes its daily routes and fails the ones separation of duties keeps from it.
