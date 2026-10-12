### Fixed: the TLS expiry alert no longer fires on the gateway's internal CA

- With `OBS_PUBLIC_PROBE_MODULE=http_2xx_internal_ca` the gateway serves 12-hour certificates that it
  renews itself, so `TlsCertExpiringSoon` fired permanently against the 14-day threshold. The probe
  target now carries its `module` label: public-CA certificates keep the 14-day/3-day thresholds,
  internal-CA certificates alert at 2 hours/30 minutes left (renewal stopped). Alerts carry a `ca`
  label and show the time left as a duration.
