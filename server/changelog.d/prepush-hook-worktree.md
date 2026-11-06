### Fixed: pre-push hook lints only new code in a git worktree
- The hook unsets the `GIT_DIR` that git exports to a linked worktree's hooks, so `golangci-lint --new-from-rev` diffs against the base instead of linting the whole tree.
- `make lint-new` runs golangci-lint with its own `TMPDIR`, so parallel runs no longer collide on its lock file.
