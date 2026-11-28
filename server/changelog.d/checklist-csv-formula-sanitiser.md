### Security: pentest checklist CSV export escapes whitespace-led formulas

- The checklist template CSV export used its own formula escaping, which a cell starting with a space (" =HYPERLINK(...)") passed through; spreadsheet programs trim the space and run the formula. It now uses the shared sanitiser every CSV export uses (`safetext.CSVCell`), and an exported file still imports back unchanged.
- Docs: none (security fix; the export's documented behaviour, formula cells prefixed with an apostrophe, is unchanged)
