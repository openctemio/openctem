### Fixed: web console self-assessment fixes (refresh time, notification tabs, phone card masking, mask detection)

- The dashboard header reads "Refresh due" once the scheduled refresh time has passed, instead of "Next 21s ago".
- Notification channels: the Events and Queue tabs show only to people who may open them (integrations:manage, as the pages and the API already require); others get no tab row.
- My work: a finding title on a phone card is masked like the table row, so a secret in a scanner title never shows in clear on a phone.
- Secret masking treats a value as already masked only when the whole value is a mask (`***`, `[REDACTED]`); `***s3cr3t` is masked.
- Placeholder and sample addresses use example.com.vn.
- Docs: none (behaviour of existing screens only; no setting or API changes)
