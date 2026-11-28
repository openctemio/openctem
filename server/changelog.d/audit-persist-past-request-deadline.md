### Fixed: an audit event is stored even when its request runs out of time

- The audit write used the request's context. When a request's deadline passed (or its client went away) after the change was made, the audit row was lost with "failed to persist audit log: context deadline exceeded", for example an integration that was created while its slow channel test made the request answer 504. The write now keeps the request's values but has its own 10 second deadline, so a change that happened is recorded.
- Docs: none (no setting or screen changes)
