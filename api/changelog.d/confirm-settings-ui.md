### Changed: settings actions that widen access or cannot be undone now ask first

- Erase personal data: the member row menu of an offboarded person now has the action (the confirmation existed but nothing opened it). It asks for the member's email before it calls the API.
- The audit log export asks first and says the file holds members' emails and IP addresses.
- Giving a member a higher role or more custom roles, widening a role (more permissions or full data access), applying a role template update, adding members to a role in bulk, binding a role to a team and approving a request to join each name what is gained before saving.
- Turning modules off lists the modules that disappear for every member and says their data is kept. The dependency dialog and the risk score recalculation dialog use the shared confirmation, with the consequence spelled out.
- Loosening the domain sign-up rules, the trust with another organization, the MCP policy, or approving a new MCP publisher asks first and lists what becomes weaker.
- Deleting a role, a team, a scope rule, a report template, an MCP application, or leaving the organization, ending a trust, rotating a SCIM token now asks for the item's name. Bulk deleting pentest templates always asks for the name or the count and lists a sample.
- Offboarding a member asks for their name, re-enabling a member and approving a join request ask first, and the account deletion dialog says what happens. API key actions sit in a row menu with delete last.
- Strings in the offboarding, setup link, end-of-access, team roles, team members and scope rules dialogs are translated (en and vi).
