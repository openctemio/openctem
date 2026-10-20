### Changed: watchers hear about comments, status changes, fix claims and assignments; people who take part start watching

- A comment, a status change by a person (a fix claim included) and an assignment now reach the finding's watchers as well as its assignee. The recipient list is decided in one place and re-checked at send time: only active members who can read the finding now are told, never the actor, never someone who stopped watching, and a team-only comment on a pentest finding never reaches a campaign client. Changes made by a scanner, the system, an integration or an AI still reach the assignee only.
- The author of a comment, the person who changes a status or claims a fix, the new assignee, and the requester and decider of an approval become watchers. A new notification preference `auto_watch` (default on, `PUT /api/v1/notifications/preferences`) turns that off; a stop on one item always wins.
- Notifications carry a `reason` (`assigned` or `watching`) and fold into the unread notification of the same type about the same finding when they come within 10 minutes (`coalesced_count`).
- The comment notification title is now "New comment on a finding" (it also goes to watchers).
- Migration `notification_reason_and_auto_watch`: `notifications.reason`, `notifications.coalesced_count`, `notification_preferences.auto_watch` (metadata-only adds with constant defaults).
