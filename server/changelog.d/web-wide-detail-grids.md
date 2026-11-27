### Fixed: detail pages, card grids and the dashboard use wide screens

- Detail pages (finding, asset, remediation task): from a 1920 px screen the panel is at most 1440 px wide and the properties rail (24rem there) sits right after it, instead of a 1024 px column with an 850 px gap before the rail at 2560 px. A wide table tab still uses the whole page. A finding's ways to prove a fix (verification, retest, retest check) sit side by side: two at 1920 px, three at 2560 px.
- Section title rows on detail pages are at most 40rem wide, so Checklist, Retest now, Add check and Remediation plan sit near their titles; a code snippet is as wide as its longest line; status and severity strips are at most 40rem wide.
- A vulnerability's page: the summary and "Who found it" use the same rule (summary up to 1440 px, "Who found it" a 24rem column beside it), so a source and its count are no longer 600 px apart.
- Label and figure rows (Executive summary process health and time to fix, Program health) flow into two to four columns as the list widens, instead of a label and its figure 1,700 px apart.
- Executive summary Top risks: a title is as wide as its column and cut by the column's width, with the full title on hover, instead of a fixed 448 px.
- The dashboard packs runs of side-by-side widgets three to a row once it is 96rem wide and four to a row from 136rem, keeping their order and leaving no empty cell; bar charts keep bars at most 48 px wide.
- Card lists (dashboard templates, SCM connections, capabilities, pentest templates, asset categories) add columns on wide screens (at least 22rem each) instead of three stretched cards; the Vulnerabilities overview puts its two charts and the trend on one row from a 2048 px screen.
- Docs: web/docs/ui-style-contract.md
