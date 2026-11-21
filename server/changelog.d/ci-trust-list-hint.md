### Fixed: CI trust list fields say they take several values

- The owners, repositories, branches, environments, events and pipeline definitions fields of a CI trust configuration (and the owners field of the setup wizard) now say that several values are separated by commas, and their examples show two values. One configuration can hold many GitLab groups; nobody needs one configuration per group.
- Docs: none (hint text only, no behaviour change)
