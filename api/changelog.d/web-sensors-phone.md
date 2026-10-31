### Fixed: a sensor that stopped taking jobs says so on the Sensors page

- A sensor whose local storage is full (it stopped claiming jobs) showed as "Degraded" while the fleet strip said "Needs attention 0, nothing to fix" and counted it as able to take jobs. It now counts under Needs attention as "storage full", is no longer counted as able to take jobs (nor as covering its zones), its phone card reads "takes no new jobs: storage full", and the sensor drawer explains the cause the sensor reported and what to do (free disk space on the host or raise the store quota; it resumes on its own).
- Any health reason the page has no word for now still counts under Needs attention ("other problem"), so a degraded sensor is never shown with "nothing to fix".

### Fixed: the Sensors page on a phone

- Metric strips whose tiles carry a detail line no longer use thirds on a phone: halves, the first tile full width when the count is odd, captions kept. Every tile's content starts at the top (a toggle tile's label sat lower than its neighbours'), and in a strip of thirds the labels keep two lines so the values line up. This applies to every page with a metric strip.
- Tab strips sit 20px apart on a phone, so three tabs with counts fit 390px; the end fade now appears whenever a tab is cut (it missed tabs that grew after the first render, such as a count arriving).
- The fleet "Refresh content" button is an icon on a narrow toolbar, and the search placeholder is shorter, so it is no longer cut.
- The status legend under the list is a one-line "What the states mean" that opens a short list, instead of a paragraph that ran under the phone browser's toolbar.
- Enrollment tokens show as one card per token on a phone (state, uses, expiry, last use, approval, Revoke) instead of a seven-column table scrolling sideways.
