### Fixed: resolving a remediation group or campaign marks its findings fixed

- Group and campaign "resolve" failed for every finding that was not already
  `in_progress` (on most groups, every finding), with no reason shown. It now
  takes each finding through the legal steps (`new → confirmed → in_progress
  → fix_applied`), with the note, for the caller's own findings, and queues a
  proof-of-fix re-check per finding, like the dedicated fix-applied action.
- A finding already `fix_applied` is skipped instead of being rewritten.
- The response names every finding not updated and why
  (`updated`, `skipped`, `failed`, `validations_queued`, `rows`); the web
  shows them in one shared "mark fixed" dialog (English and Vietnamese).

### Behaviour change: a group or campaign resolve never closes findings

- `status: "resolved"` on `POST /findings/remediation-groups/{key}/resolve`
  and `POST /remediation/campaigns/{id}/resolve` is refused (400), even with
  `findings:verify`: each finding is closed by its own evidence (a covered
  scan, a retest or a reviewer on the finding). The campaign response changes
  from `{resolved}` to the result above.
- Any bulk fix claim now queues the proof-of-fix re-check.
