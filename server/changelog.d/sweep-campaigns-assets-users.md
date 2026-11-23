### Fixed: campaign and console user lists keep their headers whole; asset overview keeps a readable width

- Campaigns: the table folds Findings closed, Owner and Tasks away by the width it has, so the Due header is never cut at 768 px; on a phone the campaign name takes the full width with its status under it.
- Asset details: the overview's risk summary and facts keep a readable width instead of stretching across a wide screen.
- Console users: the table folds Signs in with, Created and Last sign-in away by the width it has, so no header is cut at 768 or 1180 px; on a phone a last sign-in time that does not fit half the card line takes the whole line instead of being cut.
- Docs: none (layout of existing pages; no behaviour, request or API change)
