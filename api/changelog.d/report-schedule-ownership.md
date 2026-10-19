### Security: report schedules are changed only by their creator or a manager, and recipients are shown only to them

- Before, any member with `reports:write` (every member by default) could pause or delete any report schedule in the organization, including the owner's executive digest, and every `reports:read` holder (viewers included) saw every schedule's recipient addresses.
- Now pausing, resuming and deleting a schedule is allowed for its creator or a holder of the new `reports:manage` permission (owners and admins); others get 403. Pausing is now audited (`report_schedule.deactivated`), and audit rows name the creator when someone else changes a schedule.
- The schedule list and detail return recipients only to the creator and managers; others see the count. Each row carries the creator's display name and `can_manage`; the Reports page shows an Owner column and hides the toggle and delete for schedules the viewer cannot change.
- Migration `002970_reports_manage_permission` adds `reports:manage` and grants it to the owner and admin roles. Custom roles that should manage everyone's schedules need it added.
