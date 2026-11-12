### Fixed: the Release Train refuses a run started from another branch and no longer waits out its timeout

- The train checks out develop's release scripts whatever branch the run was started from. A run started from main used main's older copy of the workflow, which gives the scripts no GitHub token: refreshing the components' built-in releases retried each one for five minutes and the plan job hit its 15-minute timeout. The plan now stops at once unless the run was started from develop.
- Refreshing a component's built-in release retries a failed read for about 30 seconds instead of five minutes (an unreadable component keeps its value, as before), and the warning names the cause.
