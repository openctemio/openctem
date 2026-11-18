### Fixed: why a scanner cannot run is shown in the viewer's language

- The reason a scanner or tool cannot run now ("No sensor has checkov", "No online sensor in this zone has semgrep
  (2 offline)", switched off, not in the catalog, not allowed by grant or local policy) was English in every
  language. It now comes from the en and vi catalogs in the New scan and Edit scan scanner picker, the workflow
  editor's tool list and node palette, and the Tools page status and detail.
- Docs: none (the console text only changes language; the English wording is unchanged)
