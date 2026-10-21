### Added: watchers on findings and remediation tasks (API)

- New table `work_item_subscriptions` (migration `work_item_subscriptions`): who watches a finding or a remediation task, with composite tenant foreign keys, an explicit subscribed or unsubscribed state and a reason. Watching grants no access.
- New endpoints, for findings under `/api/v1/findings/{id}` and for tasks under `/api/v1/remediation/tasks/{task_id}`: `GET participants`, `PUT subscription` (the caller's own bell), `POST watchers` (add up to 10 people, all or none; needs `findings:assign` or `remediation:write`) and `DELETE watchers/{user_id}` (yourself with read access, others with the write permission; audited). A person who cannot be added gets one generic answer. 50 watchers per item at most.
- The list names watchers only to callers with `team:members:read` who are not pentest clients, never with emails; watchers who left or lost data scope are hidden.
- Offboarding deletes the member's watched items in its transaction (`removed_watches`); erasing personal data deletes any row left.
- Adding or removing another person is audited as `work_item.watcher_added` and `work_item.watcher_removed`.
