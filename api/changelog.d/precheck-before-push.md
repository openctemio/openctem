### Added: `make precheck` and a pre-push hook

- `make precheck` brings a branch up to date with the branch its pull request targets (merge when it is already pushed, rebase when not; message catalogs merge key by key), stops on a conflict so it is resolved locally, warns about other open pull requests that change the same files, then runs the lint and static checks CI gates on for the components the branch changes (API: gofmt, go vet, staticcheck, golangci-lint on new code; web: prettier, eslint, tsc, the separator gate and sorted catalogs).
- The pre-push hook (enabled by `make hooks`) refuses a branch that is behind its base and runs the same checks, without changing the branch.
