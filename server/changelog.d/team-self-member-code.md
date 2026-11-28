### Fixed: giving roles to a team you belong to says why it is refused

- `PUT /groups/{id}/access` (presets) and turning on a team that carries roles, by a non-owner who is a member of the team (a team's creator joins it as its owner), now answer 403 `TEAM_SELF_MEMBER` ("You are a member of this team, so giving it roles would raise your own access. Ask the organization owner to do it.") instead of `TEAM_SELF_JOIN`, which said the caller had added themselves to the team. The rule itself is unchanged.
- Docs: server/docs/architecture/authorization-matrix.md
