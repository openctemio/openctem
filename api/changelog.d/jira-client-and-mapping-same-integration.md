### Fixed: the Jira client and its mapping come from the same integration

- With several Jira integrations, the outbound client was the first connected
  one whose credentials worked, while the mapping (project, priorities,
  status maps, routing) was read from the first connected one even when its
  credentials did not. Tickets could be filed with another integration's
  mapping. Both now come from the same integration.
