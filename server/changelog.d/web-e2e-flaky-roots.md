### Fixed: a cold page load could throw a render error, and two lists moved while loading

- A page opened with a cold cache could end with "Minified React error #467": the language catalog arrived while React was rendering and the component waiting for it was replayed with hooks after `use()`. The wait is now its own hook-free component.
- Findings on a phone: the "Informational hidden" chip is drawn only once its count is known. Before, it appeared first and was withdrawn when nothing was hidden, which moved the list up by a row.
- Assets: the Monitoring column joins the columns that hide on a narrow table (after open findings), so the list no longer scrolls sideways at 1440px with the sidebar collapsed.
