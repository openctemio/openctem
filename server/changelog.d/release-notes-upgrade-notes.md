### Changed: release notes open with the upgrade notes, and the changelog has a section per release

- The GitHub Release of each version now carries its changes ("Changes in vX.Y.Z"), led by an **Upgrade notes** block: what to do before upgrading, then the behaviour changes, removals and deprecations. A release's changes are the entries its tag added since the previous release, so a hotfix lists only its own.
- `server/CHANGELOG.md` has a section for every release again (v0.15.6 to v0.21.0 were missing), and the develop follow-up of each release adds the next one.
- Docs: server/changelog.d/README.md
