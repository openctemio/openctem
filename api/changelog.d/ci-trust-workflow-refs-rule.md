### Security: a CI trust can admit only the organization's central workflow

- **New trust rule `workflow_refs`** (GitHub and GitLab): a CI trust
  configuration can list the pipeline definitions it admits, as
  `<path>@<ref>` with a pattern in the ref. GitHub matches the token's
  `job_workflow_ref` (`acme/security/.github/workflows/scan.yml@refs/heads/main`),
  so only jobs that call the central reusable workflow report and get a
  verdict; a pull request that edits or adds a workflow file is refused with
  `workflow_not_allowed`. GitLab matches `ci_config_ref_uri`.
- A token without the claim is refused when the rule is set; the rule is
  refused on save for Azure Pipelines, Bitbucket, CircleCI and Jenkins, whose
  tokens do not name the definition. At most 20 entries; the path is exact.
- The trust preview shows the token's pipeline definition, and the CI/CD
  trust form and pipeline snippet show the rule.
