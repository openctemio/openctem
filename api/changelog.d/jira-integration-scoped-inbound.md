### Security: a Jira change moves only the links of the integration that sent it

- An organization with two Jira integrations (two sites, or Cloud and Data Center) could have a change to `SEC-1` on one site move the findings linked to `SEC-1` on the other. An inbound delivery now acts only within the integration named in its URL and signed with its secret: links are matched by the issue's id, then by key within that integration; the browse URL is built from that integration's site, not from the payload; the mapping, allowed projects, profile, campaign epic and refusal comment all come from that integration.
- A moved issue (new key) is still matched by its id.
- Pushes and comments on an existing link go to the link's own integration (before: the organization's first connected Jira). A finding's ticket URL on another site is never pushed through the default integration.
- Create ticket, create task issue and link issue accept an optional `integration_id`; without it the default integration is used, as before.
- An inbound delivery no longer skips the project check when the integration's client cannot be built.
