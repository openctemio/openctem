### Fixed: run-once effects in the console read their latest values without lint suppressions

- The ranked-bars move animation, the sign-in notice, the sensor onboarding auto-start and the pairing-code lookup now run once through effect events, so they always use the current translation function and callbacks instead of a captured one. No behaviour or request count changes.
