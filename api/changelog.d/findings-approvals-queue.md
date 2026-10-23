### Fixed: approval requests show the finding and keep a reason that failed to send
- The approve and reject dialogs show the finding being decided (title, priority, severity, CVE, asset), the whole justification and a link that opens the finding in a new tab, so a four-eyes decision is never made blind.
- Approve and Reject are buttons on each pending row; your own requests say "Your request" instead of offering disabled actions.
- A reject that fails keeps the dialog open with the reason as typed and says why under the field.
- Column headers no longer offer a sort that only ordered the 20 rows on screen.
- A failed load shows the error inside the list, keeping the page header and tabs; Refresh spins while it reloads and no longer shows a toast.
- Dates read in the app's language; status badges use the theme's status colours; titles and justifications render as isolated plain text.
