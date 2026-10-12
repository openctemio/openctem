### Security: the platform assigns each job's tier from the tool contract

- The grant check at dispatch now compares the sensor's tier ceiling with a tier the platform assigns from the tool contract the sensor reported (RFC-055 §6.3). It is the highest of:
  - the floor of the capability the job runs, or the catalog rule for a job without a capability;
  - the tier the tool's descriptor declares;
  - T2 for a declared side effect;
  - T2 for a tool the operator installed (origin `adapter`, unverified until it is classified).
- A tool's own tier can only raise the tier, never lower it below the capability's floor. A tool or capability the platform does not know stays T2.
- `sensor.ToolTrust` gives a tool's trust level: `builtin` or `unverified`.
- A sensor without a manifest is checked as before, by the catalog rule (one release train, TC12).
