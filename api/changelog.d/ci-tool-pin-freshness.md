### Changed: weekly check of the inline tool pins

- A weekly workflow compares the tool versions pinned inline in workflows, Makefiles and Dockerfiles (`.github/tool-pins.tsv`) with their newest stable releases and keeps one issue, "Tool pins to bump", up to date. It needs only `issues: write` and opens no pull request, so a person or an agent makes the bump and CI runs on it.
- No operator action.
- The development image installs golang-migrate v4.18.1, the version CI, the migrations image and the all-in-one image use; the freshness manifest now covers all four pins.
