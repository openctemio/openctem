### Security: binding a GitHub App installation needs an owner of the GitHub organization

- Completing the GitHub App install now checks that the person owns the
  installation's account: an active admin of the GitHub organization (matched
  by organization id) or the GitHub user account itself. Before, any member
  who could see the installation could bind it to their own OpenCTEM
  organization, and the first binding won, so the real organization lost its
  gate check and pull request comments.
- The install link's state is single-use (shared store across replicas; the
  bind fails closed when the store is unavailable), the binding route needs
  step-up, and the GitHub user token obtained for the check is revoked right
  after it.
- Deployments: add the **Members: Read** organization permission to the
  GitHub App (`docs/how-to/github-app.md`); without it no organization
  installation can be bound.
