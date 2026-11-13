# Unreleased changes, one file per change

A pull request with a user-visible change adds **one new file** here instead of
editing `server/CHANGELOG.md`. No two pull requests touch the same file, so
changelog entries never conflict, whatever order the merge queue takes them in.

## Add an entry

Create `server/changelog.d/<short-slug>.md` (lowercase letters, digits, `-`, `_`,
`.`; the branch name is a good slug):

```markdown
### Security: deactivated access groups stop granting access at once

- What changed, who it affects, and the migration number if there is one.
- **Upgrade note:** anything an operator must do.
```

Name the user documentation of the change in a `Docs:` line: a page of the public docs site,
a path in one of the project's repositories, or `none` with the reason. A release never ships
a change nobody can read about; API CI refuses a new fragment without it:

```markdown
- Docs: https://docs.openctem.io/sensors/proxies/
- Docs: none (internal refactor, no behaviour change)
```

A file may hold several `### ` sections. The category is one of, in release
order: `Security`, `Behaviour change`, `Removed`, `Deprecated`, `Added`,
`Changed`, `Fixed`.

To change an entry that is already merged, edit its file. To drop it, delete
the file.

## Checks

`python3 server/scripts/changelog.py check` runs in API CI (pull requests and the merge queue).
It refuses:

- on a pull request, a fragment it adds without a `Docs:` line (`--docs-base`);
- a fragment without a valid `### <Category>: <title>` heading or text;
- an entry (`### `) written under `## Unreleased` in `server/CHANGELOG.md`;
- merge-conflict markers in any tracked text file of the repository.

`python3 server/scripts/changelog.py preview` prints the assembled Unreleased
section. The release train adds it to its run summary.

## At release

A release's changes are the fragments its tag's tree has and the previous
release's tree lacks (`changelog.py notes --ref vX.Y.Z --since-previous vX.Y.Z`),
so hotfixes and a late fold never mix releases.

- The GitHub Release carries them under "Changes in vX.Y.Z" (`.github/workflows/release.yml`).
- Release Publish's develop follow-up pull request (the merge of main back)
  folds them in a commit of its own (`.github/scripts/release/post-release.sh`):
  `changelog.py release vX.Y.Z --ref vX.Y.Z --since-previous vX.Y.Z --date <tag date>`
  writes `## vX.Y.Z (date)` under Unreleased and deletes those fragments.
  Fragments merged after the cut stay for the next release.

The release branch itself is not changed, so its tree stays byte-for-byte equal
to develop's. If a follow-up pull request was lost, run the same command for each
missing release, oldest first. (Fragments shipped up to v0.11.0 were folded in one
catch-up under `## v0.11.0 and earlier` with `changelog.py archive`; v0.15.6 to
v0.21.0 were folded per release with the command above.)

## Upgrade notes in the release notes

Write what an operator must do as a bullet that starts with `**Upgrade note:**`
(start it with "no action." when nothing is needed but the change is
noticeable). The release notes open with an **Upgrade notes** block: every
such line under "Before you upgrade", then the titles of the Behaviour change,
Removed and Deprecated sections.

## Operator headings in the release notes

A pull request is labelled `notes:migration`, `notes:destructive-migration`, `notes:identity` or
`notes:api-contract` automatically by the files it changes (`.github/workflows/pr-hygiene.yml`).
When the release is cut, the fragments of those pull requests are also listed under an
**Upgrade notes** block, grouped by those headings, ahead of the categories. Write the upgrade
step in the fragment itself, as before; the block only points readers at it.
