### Changed: automatic coverage stops starting runs that no sensor takes

- After 3 coverage runs of a capability in a row end with no sensor taking the work (`NO_SENSOR`), the capability is paused for the organization with the reason "no sensor took its last runs" instead of being started again after every back-off. Administrators get the usual "Coverage paused" alert with a link to the sensors, and each asset's coverage shows the paused reason.
- It resumes by itself when the organization's sensors, their grants or local policies, zone assignments or shared-sensor setting change, or at a probe run 2 hours later (doubling after each further unclaimed run, at most 48 hours).
