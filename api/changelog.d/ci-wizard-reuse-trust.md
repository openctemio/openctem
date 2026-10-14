### Fixed: connecting a pipeline twice no longer dead-ends, and the GitHub snippet starts on the pinned release

- When a trust configuration already admits the organization, "Connect a pipeline" reuses it and shows its snippet. It no longer fails with "name already exists" or the plan limit.
- The wizard asks for the default branch. The GitHub snippet scans pushes to that branch, not always `main`, and tells you where to save the file.
- The GitHub snippet grants `security-events: write`, which the openctemio/ci reusable workflow needs to start. The Azure Pipelines, Bitbucket and CircleCI snippets run the pinned release image instead of the moving `edge` build.
