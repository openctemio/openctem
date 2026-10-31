### Changed: CI/CD settings on one page, Connect a pipeline in the header

- The CI/CD **Trust and gate** tab is now **Settings** and shows every section on one page, in the order a pipeline is set up: Trusted pipelines (with the OIDC requirement and the recent refused pipelines), Gate policy, Pull request feedback and Break-glass. The Section picker is gone; `?section=` links scroll to their section.
- **Connect a pipeline** sits in the CI/CD page header on every tab (owners and administrators).
- Trust configurations are compact rows (provider, scope, last used, actions); the issuer and audience stay in the edit form and the pipeline snippet. The OIDC requirement is one line while it is on and a warning only while CI sensor keys are still accepted. The refused pipelines list shows the latest three, the rest on request.
- The tab panel is linked to its tab (an accessibility fix).
