### Fixed: the query editor is wide enough to read

- Findings, assets and scans in Query mode: the filter tokens step aside (their values are in the query text) and the editor takes the toolbar row's free width up to Views, Group and Display, so a query reads on one line instead of wrapping inside a narrow box.
- The expanded editor follows its text: two lines at least, eight at most, then it scrolls. It breaks lines at spaces only, never inside a condition such as `practice!=compliance`. The drag handle and the remembered dragged height are removed.
- On a phone in Query mode the chips row starts below the toolbar's actions instead of running under them (assets: "Hiding 8 names awaiting review").
- Scans: the query editor shows its example placeholder in English and Vietnamese instead of a text key.
- Docs: web/docs/ui-style-contract.md (list toolbar, Query mode), server/docs/architecture/query-language.md
