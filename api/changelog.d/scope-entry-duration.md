### Fixed: Add to scope picks a duration the policy allows
- The add and edit scope entry dialogs offer a compact duration choice (7 days, 30 days, 90 days, 1 year, Permanent, Custom date) that fits a phone screen and shows the date the entry expires on.
- The default is the longest duration the organization allows: an intrusive (T2) entry defaults to the owner's limit (30 days unless an owner changed it) instead of Permanent. Permanent is offered disabled, with a link to the owner setting, when the organization does not allow it; a member request never offers it.
- No error is shown before the user acts: a neutral line says what will happen (approvals needed, expiry date), and the dialog names the tools each tier runs and offers "Verify domain" when domain proof is needed.
