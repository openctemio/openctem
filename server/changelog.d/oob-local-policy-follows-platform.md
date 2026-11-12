### Behaviour change: a sensor's local policy no longer keeps callback jobs away; the install policy leaves allow_interactsh out

- A job that asks for out-of-band callbacks (interactsh) is no longer held back from a sensor whose reported local policy does not allow them: the sensor runs it without callbacks and its result says why (`oob` state `unavailable`, reason `local_policy`). The organization's own interactsh switch still refuses such jobs when it is off.
- The local policy the console renders for a new sensor no longer sets `allow_interactsh: false`; it keeps the line as a commented example. A policy without the key follows the platform, and callbacks only ever use the sensor's own interaction server (`SENSOR_OOB_SERVER`), never a public one.
- The sensor page's help texts say so.
