### Changed: a changelog fragment names the user documentation of its change

- API CI refuses a fragment a pull request adds without a `Docs:` line: a page of the public docs site (`https://docs.openctem.io/...`), a path in one of the project's repositories, or `none` with the reason. Fragments already merged are not checked. The documentation site lists every change of a release from these fragments, so a shipped feature without documentation shows up at review time instead of after the release.
- Docs: server/changelog.d/README.md
