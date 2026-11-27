### Fixed: Findings list rows keep one height, and the title has room

- Signals and EPSS: a finding in KEV and used by ransomware stacked its EPSS bar, KEV chip and Ransomware chip on three lines, so its row was two or three times taller than the others. The cell is now one line: the EPSS bar, the KEV chip, then "+1" for Ransomware (its words in the tooltip and the accessible name).
- Columns: the Title column takes the spare width instead of Location (Location 144, up to 176; Title from 248), so a CVE id with a short name reads whole at 1024 px with the sidebar open.
- List toolbar: the Group select no longer shows the keyboard focus ring after a mouse choice; Tab and the arrow keys still show it.
- Notices: the text of a full-width notice (the vulnerability data warning, every Alert) was held to a reading width of about 700 px, three short lines beside an empty half box on a wide screen; it now uses the notice's width. Body text elsewhere keeps the reading width.
- Layout matrix seed: one finding with a long title, EPSS, KEV and ransomware use, so the matrix sees the busiest row.
- Docs: none (layout fix, no behaviour change)
