### Fixed: admin console lists waste no row and fit a tablet

- Lists without a search box (roles and their holders, approvals, platform sensors, sign-ups, target mappings, admin activity, content pack channels, blocked-name exceptions) show their name and count at the start of the toolbar row, with the filters, the list's own action and Display on the same line. Before, Display or the phone's Filters button stood alone on a row under the name. The shared list toolbar has a title slot for this (`ListToolbarTitle`, `DataTable` `toolbarTitle`).
- Overview: each "Needs attention" problem is one link, its words and its action ("Inspect") with an arrow, instead of text over a lone button.
- Admin activity: whether the audit log verifies is one line in the page header; a broken chain is still shown in full above the list. Export sits in the toolbar row.
- Approvals: how approvals work is said under the list. Limits: how the default limits apply is said under the table.
- Platform scanning, while shared sensors are not available: Policy and Blocked names are two tabs, so the exceptions list is no longer under the policy cards. Page tabs there are one swipeable row on a phone.
- Content packs: the pack list comes first; the not-delivered notice, the channels and the signing key follow it at full width (the copy button no longer runs past its column at 1024 px). Packs and channels have their own phone cards.
- Threat intelligence: the bundle's sources are one list of facts with the others, not a table inside the card.
- Tablet: the row menu stays in view on administrators, role holders, target mappings and blocked-name exceptions; the activity table and the organizations list no longer cut a column header at 768 px.
- Phone: sign-up, role-holder, pack and channel cards reach the end of their row; the platform sensors info mark sits beside the count; health values ("0.2 ms") never break inside themselves; "Publish announcement" is an icon beside the title; CAPTCHA's On or Off leads its description.
- Words: the terminal sign-in client and CAPTCHA's site key read in Vietnamese; the announcements empty state reads "No announcements".
- Docs: none (layout and wording fixes of existing console pages, no behaviour change)
