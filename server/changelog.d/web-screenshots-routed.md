### Added: web screenshots are planned by asset coverage

- The capability `capture.screenshot` is routed to the sensor tool `webshot` (a headless browser in the sensor's `browser` image). Every web service gets a screenshot pair every 30 days, and again at once (at most daily per asset) when a probe changes its title, status code, redirect target or favicon.
- Screenshots stay off by default and are now off for real: while an organization has `web_screenshots_enabled` off (or the setting cannot be read), the pairs are paused with the new readiness reason `feature_off` and no job is created, so the picture is not even taken. Turning the switch on makes the pairs due.
