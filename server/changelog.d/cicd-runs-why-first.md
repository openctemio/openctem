### Changed: CI/CD runs show why first, and refused pipelines are announced

- **Runs** uses the console's shared table: a phone gets one card per run instead of a table cut off at the right edge, with the same pagination and Verdict filter as other lists. The repository shows without its code-host prefix, with the provider icon and the workflow name.
- A run's panel leads with the verdict, the findings summary and the blocking reasons; provider, commit, tools and posting status follow under **Details**. The pull request number is in the panel's subtitle.
- **Pipelines** tells a CI writer when pipelines were refused in the last 7 days ("5 pipelines were refused in the last 7 days. See why"), linking to the refused list under Settings. A refused pipeline never appears in the list, so a wrong trust rule no longer looks like silence.
- The Inactive metric tile is gone (its count is on the Show inactive switch) and the Runner column moved out of the pipeline list (an unsupported runner already shows as Degraded; the version is in the pipeline panel).
