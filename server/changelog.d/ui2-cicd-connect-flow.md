### Changed: CI/CD connects a CI provider in four plain steps, shows why jobs are refused, and splits its setup into Connections, Gate and Pull request feedback

- "Connect a CI provider" (CI/CD page) asks for the provider and, for a self-managed GitLab, its address, shown exactly as its tokens carry it (https, no trailing slash); a private address gets a warning that the platform must reach it.
- Which projects: every project in several groups at once, projects directly in groups, or a list; which branches: only protected branches and tags by default on GitLab, with a warning when a whole group is opened to every branch.
- The last step waits for the first run (runs and refused jobs are read every 10 seconds while the step is open) and shows a refused job with its reason.
- Each trust configuration shows its last accepted job and its refused jobs of the last 7 days; a refusal offers a one-click fix ("Allow branch", "Allow project", "Add this pipeline file" with the token's exact value) that opens the configuration with the change filled in, saved only by Save.
- Pipeline definitions, events, environments, audience, fork pull requests and scope are folded under "More rules"; pipeline definitions are built from project, file and branch, with the three places a top-level configuration file can live explained.
- "Check a sample token" names the cause of a failed check (private address not allowed, provider unreachable, address differs with a "Use" button, audience, expired, signature).
- The Settings tab becomes three tabs: Connections (a status line "2 connections working, last accepted job 5 min ago, 3 jobs refused: see why", then one line per configuration that opens a sheet with Health, Rules, Scope and the pipeline snippet; "Require OIDC for CI results" folded under "Organization rules"), Gate and Pull request feedback. Break-glass moves to the Runs tab, next to the run it unblocks, with past overrides folded.
- "Add trust" is gone: "Connect a CI provider" is the one way in, and its first step offers "Fill in every rule yourself" for the full form.
- Gate policies and break-glass overrides name a repository by its name and pick it by name, never by its internal id.
- Old links (`?tab=setup` and its `?section=trust|refused|gate|feedback|break-glass`) open the new tab and the address is rewritten.
- A private CI address now says that a platform administrator can allow it.
- Docs: none in this repository (UI copy and in-app help only); the public CI guide is updated in the docs site.
