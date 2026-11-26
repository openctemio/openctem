### Changed: a pentest campaign's Checklist tab is a calm, dense work list

- Items are rows of one grouped table (a section per group) instead of a card per item: the ID, the test and its result on one line, the assignee from tablet width. A section header shows how many of its items were tested in a thin bar coloured by result, and how many failed.
- Progress reads "12 of 38 tested" with the counts of passed, failed, N/A and untested items; N/A no longer counts as tested, so a checklist marked all N/A is no longer shown as 100%.
- The result is a compact control in the row (icon and word, no second status icon); a row opens the item's details (guidance, assignee, findings, evidence, notes, Create finding on a failed item) in a drawer.
- Selecting rows (or a whole section, or every row from the header checkbox) shows the bulk bar with Set result and Assign; the separate "Select all shown items" row is gone.
- Remove checklist and Review changes moved into the checklist's "..." menu; a campaign with several checklists switches between them with a Checklist filter instead of a row of buttons.
- Docs: https://docs.openctem.io/pentest/checklists/ (the "Checklist tab" text needs an update for tested-of-all progress, the Checklist filter and Remove in the "..." menu; the page has no screenshots)
