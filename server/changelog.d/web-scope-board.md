### Changed: the Scope page follows its design board

- The Scope summary counts known targets: In scope, Excluded, Pending proof (domains waiting for their DNS record) and Found but unknown (opens the assets no entry covers). Excluded and Found but unknown come from `GET /scope/stats` (`inventory_excluded`, `inventory_not_covered`); until the server sends them they read "Not measured".
- "Check target" beside the summary asks the scope gate (`POST /scope/check`, a dry run: nothing is sent to the targets) whether up to 50 targets are in scope, why, and offers the fixes the caller may take.
- The entries list shows "Authorized by" (ownership, a CI trust, a bug bounty program, a letter, a member's attestation, and who added it) in place of Reason and Added by; the reason is in the row's tooltip and Edit. The exclusions list shows the reason under Why.
- Kind and Status moved into one Filters popover (a sheet on a phone), so the toolbar keeps the list switcher and never scrolls sideways; phone rows are cards with plain facts instead of label/value fields.
- The Add to scope Duration is a segmented control; the approvals panel is translated.
- Shared: the "last used / last seen" column fits the longest Vietnamese relative time (168 px, longer text ends in an ellipsis with the exact time in the tooltip). API keys: a revoked key reads "Revoked" under Expires. Delete organization: a "Who and what is affected" box with the member, asset and finding counts. Security overview: four summary tiles and "Review N" with the count.
- Shared list toolbar: on a phone, a list with its own filter control keeps its other toolbar tokens drawn (the Scope list switch was hidden there with nothing to reach it).
- Audit log: every resource type the server writes has an English and a Vietnamese label (a Vietnamese log no longer shows "Verified domain").
- Roles, members and the role detail: the built-in roles' names and descriptions follow the console language.
- Docs: none (presentation of existing pages and labels; no request, permission or API behaviour changes)
