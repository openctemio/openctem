### Fixed: lists and overview charts fit their frame and read in the console's language

- A long task, campaign or other row name no longer widens a table past its frame: the name column is sized by its floor and the room left, so the Deadline and Due columns of Tasks and Campaigns are no longer cut at 1440 px.
- Vulnerabilities and the other exposure overviews: severity names, the status names and the series name in the charts' legends and tooltips read in Vietnamese, the legend keeps severity order (Critical, High, Medium, Low) in the muted caption size, and the axes and tooltips follow the shared chart defaults.
- A page header with a view switcher and actions keeps them together on the right when the row is full, so the switcher is never left alone on a row at 1024 px.
- Certificates: at 1024 px the table folds Issued on, Fingerprint and Detected away instead of scrolling sideways, and the Expires on date and status line up to the right.
- Docs: none (layout and wording of existing pages; no behaviour, request or API change)
