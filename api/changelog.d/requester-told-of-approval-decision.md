### Fixed: the requester of a false-positive, accepted-risk or severity request is told how it ended

- When a request is approved or rejected, its requester now gets an in-app notice with the outcome and the finding title (a group exception: the number of findings). The justification and the rejection reason are never in the notice. Nothing is sent for the requester's own withdrawal, to a requester who left, or to one who can no longer read the finding.
- Removed the "Mentions" notification preference from the settings page: nothing sends that notification yet, so the toggle changed nothing.
