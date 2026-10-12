### Behaviour change: a secret already on the default branch no longer blocks every pull request

- The CI gate still fails any run that adds a committed secret, and every
  default-branch run while a secret is open. A secret already open on the
  default branch is now a non-blocking `secret_pre_existing` note on pull
  request and other branch runs, so one historic secret does not block every
  pull request until it is triaged (RFC-077 G-9, owner decision 2). Without a
  default-branch baseline every secret counts as new and fails.
