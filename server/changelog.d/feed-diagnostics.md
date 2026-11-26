### Fixed: the vulnerability feed says which feed failed and why

- Platform console: the freshness banner names each feed whose data is missing or out of date,
  why (the feed's last error, in the reader's language) and the fix, with a link to System >
  Threat intelligence. `GET /api/v1/admin/threat-intel/freshness` conditions carry
  `limit_seconds`, `error_code`, `error_params` and `failing_since`.
- Web app: the banner every user sees also says which data is affected (the vulnerability
  catalog, the known exploited list, the exploit likelihood scores). `GET
  /api/v1/threat-intel/freshness` adds `sources` (feed names only, no error detail).
- New feed error codes instead of `unreachable`: `blocked_address` (the host is on a private
  address that is not allowed), `proxy_refused` (the feed proxy answered the CONNECT with a
  refusal, param `status`), `proxy_unreachable` (the feed proxy cannot be reached) and
  `config_invalid`.
- A `VULNFEED_BASE_URL` the API refuses at start-up (a blocked private address, or not an https
  URL) is now a feed status error on the vulnerability bundle card (`blocked_address` or
  `config_invalid`, with the setting and host) and alerts the administrators at the next check,
  instead of one log line.
- Feed delivery: a platform sensor that cannot relay says why: `inactive`, `version_too_old`
  (with `min_version`, v0.36.0), `no_signing_key`, `relay_off` (`SENSOR_FEED_RELAY=0` on its
  host) or `no_capability` (the sensor reports too little to tell). The reason is read from the
  sensor's own report and only explains; it never makes a sensor eligible.
- Docs: https://docs.openctem.io/operations/vulnerability-feed-setup/
