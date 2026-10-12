### Added: role templates for the people in a CTEM program

- `GET /api/v1/roles/templates` (`team:roles:read`) lists twelve starting
  points for a custom role: program lead, security analyst, vulnerability
  manager, remediation owner, AppSec engineer, scan operator, validation
  engineer, external tester, threat intelligence analyst, risk approver,
  auditor and executive viewer.
- A template grants nothing. A role is created from it with the usual
  `POST /api/v1/roles`, so the grant ceiling applies: nobody can build a role
  above their own permissions. Tests keep separation of duties (the requester
  never approves, the fixer never verifies, the scope writer never approves).
