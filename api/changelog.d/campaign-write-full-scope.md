### Security: changing a campaign needs every one of its findings in your scope

- A member restricted by data scope could update, pause, delete, refresh or
  open a Jira epic for a campaign shared with another team as soon as one of
  its findings was theirs. Those changes now need every finding of the
  campaign (and its asset) in their scope, or an empty campaign they created;
  otherwise they answer 403. Seeing the campaign still needs only one finding
  in scope, and resolve still changes only their own findings.
- A restricted member's new or changed campaign scope (`finding_filter`) must
  be theirs too: creating a campaign over, or re-scoping one onto, another
  team's findings, assets or CVEs answers 403 and saves nothing.
- The restricted campaign list examines every campaign of the organization
  instead of the first 1,000, so later campaigns are no longer missing.
