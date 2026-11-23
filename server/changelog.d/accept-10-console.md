### Changed: the layout acceptance matrix also checks the platform console

- The viewport matrix and layout checks used to accept the tenant app's pages now run on platform console pages too (`web/console/e2e/specs/layout-matrix.spec.ts`, under the console's own Playwright config), signed in as the console suite's administrator, with the console's list data.
- Docs: none (test tooling only; no product behaviour, request or API change)
