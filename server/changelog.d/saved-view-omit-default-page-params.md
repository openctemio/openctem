### Fixed: saving a view in Basic mode works against any API version

- The console sends `page_params` with a saved view only when it holds something other than the page's default. A view saved in Basic mode sends no `page_params`; a view saved in Query mode sends `{"mode": "query"}`. Saving no longer fails with "Invalid request body" against an API that predates the field.
- When saving a view fails, the Save view dialog stays open with the name and choices kept, and says why.
- Docs: web/docs/findings-list.md
