### Changed: the Sensors health metrics count every sensor that needs a look, and filter on click

- "Needs attention" now counts enabled sensors that are not connected (stale, offline or never connected). It also counts sensors that fail or have not sent their setup check, and sensors whose identity was cloned. The page used to drop the setup-check and cloned-identity reasons the API sends.
- "Fleet health" filters the list to the sensors that are not connected when there are any. Needs attention, Updates, Zones and protocol v1 filter or group as before. Jobs stays a number.
- The "Run style" filter shows only while the organization still has a one-shot sensor.
