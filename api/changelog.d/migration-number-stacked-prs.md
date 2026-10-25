### Fixed: migration numbers account for stacked pull requests

- `make -C api migration-new` read only pull requests that target develop, so a number already taken by a stacked pull request (one that targets its parent branch) was handed out again. It now reads every open pull request.
