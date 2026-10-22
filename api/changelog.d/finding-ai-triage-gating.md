### Fixed: AI triage on the finding page respects permissions, opt-in and its own endpoint

- The AI triage button now shows only to users with the permission to run it (`ai_triage:trigger`) in an organization that turned AI triage on. The explanatory "not available" popover is gone: where it is turned on is described in Settings > AI.
- Users without `ai_triage:read` no longer send the AI triage configuration and result requests, so the finding page no longer shows a 403 error toast for them.
- The "AI analysis" section of the Overview tab is read from the finding's AI triage endpoint instead of the first page of the activity feed, so it no longer disappears once more than 20 newer activities exist.
- No API change.
