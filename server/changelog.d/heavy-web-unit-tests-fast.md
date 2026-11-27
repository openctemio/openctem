### Changed: heavy web unit tests finish well inside their time limit

- Test-only. Dialog and form tests no longer pay a timer hop per user action (`userEvent.setup({ delay: null })`) or one key event per character of a long value (`enter()` in `web/src/test/user-input.ts` pastes it); the toast library's stylesheet is not added to the test document; the quick-scan preview test waits for the request that carries the scanner (the preview follows the targets by 400 ms, so on a slow machine it asks once before the scanner is chosen); the dashboard accessibility test is split so no test carries two axe runs, and the gallery run covers the dialog alone.
- Docs: none (test-only)
