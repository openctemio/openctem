### Security: list reads refuse a non-administrator caller without a resolved scope

- The list compiler used by the asset list, its IP contexts and network counts, the exposure items, certificates, technologies, web endpoints, the posture views and the assistant's asset search read a caller who was neither an administrator nor tied to a user as unrestricted. Such a caller is now refused, a user-less API key reads an empty scope, and a missing data-scope enforcer or a scope that does not resolve is an error. The data-scope resolver now tells "sees the whole organization by right" (owner, administrator, a role with full data access) apart from "nothing resolved", so members holding a full-data role keep their lists. Members and administrators see what they saw before.
- Custom queries and search suggestions no longer refuse a member who holds a full-data role (they answered "data scope did not resolve").
- Docs: server/docs/architecture/authorization-matrix.md
