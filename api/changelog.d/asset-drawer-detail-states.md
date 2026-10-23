### Fixed: asset drawer and asset page show honest states
- The asset drawer closes after the asset is deleted from it and shows the edited asset once the list refreshes.
- The Findings tab lists open findings only, so the tab badge, the list and the footer count agree; severity chips come from the asset's own counts, finding statuses use the shared status badge (a duplicate is no longer "Resolved"), and a failed load offers retry.
- The Owners tab and the scope and scanning section show an error with retry instead of an empty answer.
- `/assets/[id]` shows a skeleton while the team loads, a no-access message without `assets:read`, an error with retry for server errors, "Not yet scored" instead of "0/100", readable type labels, and its text is translated (en, vi).
