### Fixed: a release whose changelog alone passes GitHub's size limit is still published

- The release workflow stopped at "Create the release" when this release's changelog was longer than the room GitHub leaves for a release text (v0.25.0, the long redesign train). The changelog is now cut before the first entry that does not fit, the generated pull request list is left out, and the text links the full list in `server/changelog.d` at the tag and the full comparison with the previous release.
- Docs: none (internal release tooling; nothing a user configures)
