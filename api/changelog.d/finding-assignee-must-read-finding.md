### Behaviour change: a finding can only be assigned to a member who can read it

- Assigning a finding (single, bulk, workflows) now needs an active member whose data scope covers the finding's asset, or who is on the pentest campaign. Before, any active member was accepted, and their assignment notice was then hidden by the inbox scope filter. A refused target gets one generic answer (`this person cannot be assigned this finding`); bulk assignment reports it per finding.
- New `GET /api/v1/findings/{id}/assignable?q=&limit=` (needs `findings:assign`, and the caller must be able to read the finding) lists only the members who can be assigned, with name, avatar and role (no emails). The finding assignee picker uses it.
