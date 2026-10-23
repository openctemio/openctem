### Fixed: asset groups list and detail are complete and honest
- `/assets/groups` loads every group (up to 1000, with a "Showing the first N of M" line) instead of the first 20, sends the search to the server, shows an error with retry when the load fails, and finishes bulk actions (refresh, dialog closed) even when the call fails. The Export button keeps an accessible name on narrow screens.
- The "Add assets" dialog searches the whole inventory on the server and leaves out the assets already in the group; the create dialog searches the server too.
- `/assets/groups/[id]` loads up to 100 members and findings, says "Based on the first N of M" where figures come from a partial set (Assets tab, breakdowns, JSON export), and shows an error with retry instead of "Group not found" when the request fails.
- Text on both pages is translated (en, vi) and sync success toasts are gone.
