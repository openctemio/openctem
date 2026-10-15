### Changed: a scoring change sends one summary instead of one alert per finding

- When a scoring model or the organization's risk scoring settings, priority rules or SLA policy change, the open findings it moves no longer send one `finding_priority_escalated` notification each. Once the recompute has finished, one `scoring_change_applied` notification per change summarizes it: findings changed, moved up (and to P0), moved down, and deadlines moved earlier (migration 002193, table `scoring_change_impacts`).
- The new event is on by default and is turned on for every channel that already receives priority escalations. Its severity follows the most urgent movement, so the channel's severity filter still applies.
- Priority escalations for any other reason (new findings, intel, asset context, controls) are unchanged.
