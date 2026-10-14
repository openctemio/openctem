### Fixed: editing a scan with a cron or RRULE schedule

- The Edit scan wizard showed a cron or RRULE schedule as "weekly" and sent it back that way, so every save of such a scan (a rename included) was refused for a missing day. The wizard now shows the stored expression and keeps it unless you replace it with a daily, weekly or monthly schedule.
