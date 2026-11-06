### Fixed: held sensor results are released once the tool's descriptor declares their types

- Reports held as `out_of_contract` (for example nuclei findings on `web_origin` assets while the sensor's descriptor did not declare that type yet) are now re-checked against the tool's current descriptor every 5 minutes and when the sensor registers a changed manifest. An item whose every type is now declared, and that nothing else refuses, is applied through the same path as a person's accept and audited as `sensor_result.auto_accepted` (actor system). Everything else stays pending for review.
- No migration.
