### Behaviour change: nuclei validations and retests keep to the web scope instead of being refused

- A nuclei validation (`validate`) or retest (`retest`) whose target host has a path exclusion now carries the organization's `web_scope`, like a scan, instead of being refused with `WEB_SCOPE_UNSUPPORTED`. The platform writes the scope; a value in the caller's payload is replaced.
- Such a job requires `net.confined@1` (`required_features`): only a sensor that itself reported it is offered the job. A sensor reports it from v0.19.0, the release whose validation and retest paths keep to the scope (sdk-go v0.25.0), so an older sensor, which would drop the scope, never takes it. Other sensors leave it queued (`not_confined`).
- When the organization has no active sensor that reports `net.confined@1`, the job is refused when it is created with `NO_CONFINED_SENSOR`, and nothing is queued.
- A validation or retest of any other web tool on such a host is still refused with `WEB_SCOPE_UNSUPPORTED`. Jobs on hosts without a path exclusion are unchanged.
