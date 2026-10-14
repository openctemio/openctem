### Security: GitLab connections accept only group or project access tokens

- Connecting a GitLab group for CI statuses and merge request notes now checks that the token acts as a bot user (`GET /user` reports `bot: true`, the user of a group or project access token) and that this user is the token's own. Before, any direct member's personal access token with the `api` scope was accepted, so the gate was posted as that person and kept working with their access after they left the group.
- A connection made with a personal token before this change keeps working until it is removed. Reconnect the group with a group access token.
