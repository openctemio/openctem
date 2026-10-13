### Behaviour change: web-scoped nuclei jobs wait for a confined sensor

- A nuclei step with a web scope (a path exclusion on its host) carries `required_features: ["net.confined@1"]`. The claim offers it only to a sensor whose own report lists `net.confined@1` (sensor v0.19.0 or later, running with its seccomp profile); a capability declared by an administrator never counts. Other sensors leave it queued, and the run page says why (`not_confined`), instead of failing it with `WEB_SCOPE_UNSUPPORTED` on an unconfined sensor.
- A step whose jobs need a confined sensor is refused when it is queued with the new code `NO_CONFINED_SENSOR` (class `placement`, never retried) when the organization has no active sensor that reports it.
- **Upgrade note:** until a sensor runs v0.19.0 with `--security-opt seccomp=…/sensor.json`, web-scoped nuclei steps fail with `NO_CONFINED_SENSOR`. Other steps are unchanged.
