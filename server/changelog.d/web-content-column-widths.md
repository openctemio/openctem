### Changed: list columns are as wide as what they hold (Findings, Assets, Vulnerabilities)

- The shared table measures the header and the rows on screen and sizes each column from its content, within its kind's floor and cap, instead of fixed widths per page. Spare room goes to the title first; when room is short the optional columns drop and the title gives way last; a chip, a date, a number or an id is never cut.
- Widths stay put while paging, sorting and refreshing; they settle again when the filters or the language change. Header and rows stay aligned and frozen columns keep their place.
- Findings, Assets and Vulnerabilities use it: at 1440 px the asset list shows 8 columns instead of 5, wide screens show the optional columns and fuller titles, and a long location or version is shown whole when there is room. Other lists keep their widths until they move over.
- Docs: web/docs/ui-style-contract.md, "Lists and tables", column sizing by content.
