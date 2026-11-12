### Fixed: coverage alerts no longer repeat while a small count flaps

- A coverage alert (gap, keeps failing, produces nothing, paused) stays one open alert per capability and kind. It is sent again only when it gets clearly worse: the count at least doubles and grows by 5 or more, at most once a day. A count going down updates the alert silently instead of notifying every administrator.
- A condition that clears and comes back within three days (was one day) comes back silently, so a failing streak on a few assets that passes and fails from run to run no longer re-alerts.
