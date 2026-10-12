# Unreleased changes, one file per change

A pull request with a user-visible change adds **one new file** here instead of
editing `api/CHANGELOG.md`. No two pull requests touch the same file, so
changelog entries never conflict, whatever order the merge queue takes them in.

## Add an entry

Create `api/changelog.d/<short-slug>.md` (lowercase letters, digits, `-`, `_`,
`.`; the branch name is a good slug):

```markdown
### Security: deactivated access groups stop granting access at once

- What changed, who it affects, and the migration number if there is one.
- **Upgrade note:** anything an operator must do.
```

A file may hold several `### ` sections. The category is one of, in release
order: `Security`, `Behaviour change`, `Removed`, `Deprecated`, `Added`,
`Changed`, `Fixed`.

To change an entry that is already merged, edit its file. To drop it, delete
the file.

## Checks

`python3 api/scripts/changelog.py check` runs in API CI (pull requests and the merge queue).
It refuses:

- a fragment without a valid `### <Category>: <title>` heading or text;
- an entry (`### `) written under `## Unreleased` in `api/CHANGELOG.md`;
- merge-conflict markers in any tracked text file of the repository.

`python3 api/scripts/changelog.py preview` prints the assembled Unreleased
section. The release train adds it to its run summary.

## At release

After the release is tagged, one pull request into `develop` runs
`python3 api/scripts/changelog.py release vX.Y.Z`. That folds every fragment
into `CHANGELOG.md` under `## vX.Y.Z (date)` and deletes the fragments. The
release branch itself is not changed, so its tree stays byte-for-byte equal to
develop's.
