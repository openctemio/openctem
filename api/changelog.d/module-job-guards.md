### Fixed: background jobs leave an organization alone when the module that owns them is off

- Program sync, the program feed reconcile and program assignment (scope), the remediation task reconcile, query tasks and Jira issue push (remediation), and the AI agent sweep (AI triage) no longer run for an organization that switched the module off or is not entitled to it. The other module jobs were already guarded and are now covered by one test per job.
- Asset coverage and asset enrichment belong to core scanning: they no longer stop when attack surface is off. Web evidence retention, VEX statement expiry, AI use-case downgrade, automation run cleanup and the scope effects, pending and attestation jobs keep running whatever the organization chose, since they enforce retention or keep the scope boundary consistent.
- A sweep over the oldest rows of every organization no longer lets an organization with the module off fill the batch and starve the others.
