### Behaviour change: Researcher is a role template, not a built-in role

- The built-in roles are owner, admin, member and viewer. Researcher (RFC-065) is now the `researcher` role template (RFC-095).
- Migration `role_template_library` gives every organization that used the built-in Researcher role (a member held it, or a pending invitation offered it) its own custom Researcher role with the same grants, and moves every assignment and invitation to it; nobody's permissions change. Organizations that never used it no longer see it. `researcher` is no longer a reserved role slug.
- **Upgrade note:** an API client that referenced the Researcher role id `00000000-0000-0000-0000-000000000005` must use the organization's own Researcher role (`GET /api/v1/roles`).

### Added: versioned role templates with updates you review, and role summaries

- New templates: CI integrator, sensor operator, researcher and bug-bounty triager (16 in all). Each template has a version.
- `POST /api/v1/roles` takes `template_id`; the role records the template, its version and its permissions at that version. A later template change never changes the role: role responses show the difference (`template`), and `POST /api/v1/roles/{id}/template/apply` applies it within your own grants, keeping the role's own edits.
- Role and template responses carry `summary`: a risk tier (low, medium, high, critical), the reasons and what the role views or changes per area, so the console no longer shows a bare permission count.
