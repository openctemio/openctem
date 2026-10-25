### Behaviour change: a sensor on the system trust store is no longer "Unhardened"

- The Unhardened tag, the posture fixes and `openctem_sensors_unhardened` no longer count `pin_none` (the sensor checks the platform certificate against the system trust store). That is the normal state for a publicly trusted certificate, and every sensor installed from the documented commands on the hosted service was flagged. The reasons are now: no local policy, tools without network confinement, bearer key. The Security posture block still shows the platform TLS check ("System trust store"), and `SENSOR_CA_FINGERPRINT` remains optional hardening.
- **Upgrade note:** the `pin_none` series of `openctem_sensors_unhardened` disappears; alert rules that select it by name need editing.
