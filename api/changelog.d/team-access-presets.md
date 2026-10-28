### Added: a team carries access, add people and they inherit it

- A team's **Access** settings name one or more presets (role templates) and a scope mode (specific assets, or all assets). Each preset becomes a managed role of the team; members inherit the permissions and the scope when they are added and lose them when they leave or their membership ends. No role needs to be created first. New routes `GET/PUT /api/v1/groups/{groupId}/access`, `POST /api/v1/groups/{groupId}/access/upgrade` and `GET /api/v1/users/{userId}/team-access`; migration `003545_team_access_presets`. See RFC-127 and the how-to "Give a team access".
- A preset follows its template: the team shows when a newer version is available and applies it on request.

### Security: teams with elevated access are the owner's

- Setting **all assets** or a privileged preset on a team, and renaming or deactivating such a team, is owner only with a recent sign-in, audited at critical severity. Adding or removing people in it needs `team:members:write`; outside members and service accounts never join an all-assets team.
- Managed roles cannot be edited, deleted, assigned to a person, used in an invitation or bound to another team, in the service and in the database.
