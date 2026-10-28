### Changed: CI runs only the jobs a change's kind needs, also in the merge queue

- New `.github/scripts/scope.sh` classifies a change finer than api/web: application code, the e2e suite (`web/e2e/`), translation catalogs, and the CI files each workflow actually uses. It only narrows what `changed.sh` selected and runs on pull requests and in the merge queue.
- A change to `web/e2e/` alone runs Web checks and Web E2E; it no longer runs the web unit tests, the all-in-one image build or CodeQL.
- A change to non-English catalogs only runs Web checks and the catalog tests plus the tests that read a catalog (new job `Web i18n tests`, about 50 files) instead of the whole suite and Web E2E. English catalogs still run Web tests and Web E2E, which find elements by English text.
- A change to a workflow or CI script runs the workflows that use it (plus Workflow Lint and the self-tests), not every workflow.
- Required check names and aggregator rules are unchanged: `Web CI OK`, `E2E OK`, `All-in-one OK`, `API CI OK` and `CodeQL OK` pass when their work is skipped for a change they cannot be affected by.
