### Fixed: scheduled scans run once per period across daylight-saving changes

- A daily, weekly or monthly scan whose time does not exist on the day the clock goes forward (for example 02:30 in a zone that jumps from 02:00 to 03:00) runs right after the jump (03:30) instead of an hour early, and the following day runs once at its time instead of twice.
- A cron schedule whose time happens twice on the night the clock goes back runs once.
