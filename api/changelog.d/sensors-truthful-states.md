### Fixed: the Sensors page offers only actions that work and gives one reason per problem

- **Rotate key** is offered only for a sensor that has an API key, in an organization that still allows them. It was offered for key-bound (paired) sensors and in organizations that require key-bound identity, where the API always refused it.
- A sensor that never connected shows one problem, "Not connected yet", with "run its install command on the host". It also said "Tools not reported, upgrade the sensor" and "install the sensor with its key", which was wrong for a paired sensor.
- An installed tool a New sensor may not run reads "passive only while New", with how to promote the sensor, instead of "not in grant" and the grant field's internal name.
- The sensor list row menu has **Revoke**, as the sensor drawer does.
- "Expect a sensor" is now "Create a pairing code first" everywhere: the API reference, the audit message and the `sensors:pair` permission description (migration 20261031112916).
