### Security: a delegated group manager changes only groups they fully cover

- Unassigning an asset from an access group, changing its ownership type and
  removing someone else from a group now need the caller to hold every asset
  the group holds (owners, admins and full-data roles are not capped; leaving
  a group oneself is always allowed). Before, a restricted manager (a BU lead
  with `groups:write`) could strip another BU's group of an asset or a member
  (research 21b M-4, RFC-050 W7). Adding members already had this cap (D13).
