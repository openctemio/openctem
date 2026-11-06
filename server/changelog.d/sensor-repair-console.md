### Security: only a re-pair code from the console can replace a sensor's key

- A sensor that used an ordinary "Add sensor" code while naming an existing sensor turned the request into a re-pair of that sensor; approving it revoked the named sensor's working key. The code now decides: an ordinary code always adds a sensor, a re-pair code always re-pairs its sensor, and an approval must name the sensor it re-pairs (`repair_sensor_id`, `409 REPAIR_NOT_ACKNOWLEDGED` otherwise).

### Added: Re-pair a sensor from the console

- **Sensors → sensor → Re-pair…**: pick why (identity lost, host rebuilt or moved, key may be compromised, new install method), optionally revoke the current key at once, run the command with a re-pair code for that sensor only, compare what the platform last knew with the host asking, and approve with the fingerprint and your second factor.
- The sensor keeps its name, zones, grant and history; its trust level returns to New. Its earlier keys are revoked and the jobs it held are taken back at approval (also when its last key is revoked). Migration `20261031113852` adds `sensor_pairings.repair_reason`.
