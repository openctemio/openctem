### Changed: Settings > Members shows its three lists as tabs on the settings frame (redesign branch)

- `/settings/members` has three tabs with counts: Current members, Pending invitations and Requests to join; the
  tab is in the URL (`?tab=`). The counts of active, disabled and offboarded members are on the Status filter.
- A member is one table line: the name opens the detail, then the membership marks and the email. Status is a
  state mark; the two-factor column is named "Two-factor". The Display menu can hide columns.
- Row actions, dialogs, confirmations, permissions and requests are unchanged.
- Docs: none (the page keeps its functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
