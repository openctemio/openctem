### Fixed: previewing a task from a query no longer fails on a finding without a title

- Previewing or creating a remediation task from a query returned "internal error" when a matching finding had no title (`findings.title` is nullable). The preview sample, the task member list, the claim-conflict and primary-holder reads and the suggestion reads now show the finding's title, then its rule name or rule id, and an empty title in the console shows "Untitled finding". A finding's message is no longer a title fallback in these lists, because a secret finding's message can quote the secret.
- The create-from-query dialog shows its translated message when the API reports a server error, instead of the raw "internal error".
