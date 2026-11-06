### Changed: targets that do not answer coverage are tracked per sensor or zone and raise their own alert

- A coverage pair whose target did not answer (unreachable, timeout) now records which scan zone or sensor tried. Its recheck wait widens (1 day, 3 days, then weekly) only while the same zone or sensor finds it silent; another zone or sensor gets the short recheck again. A success clears it.
- These pairs count as unreachable instead of as coverage gaps, and raise one alert per capability on change: "Coverage: <capability> targets unreachable" with the count (never the targets), sent in-app and to integrations like the other coverage alerts.
- The asset's Coverage section says "unreachable from your sensors", or names the organization's own zone or sensor that tried (`unreached_from` on `GET /assets/{id}/coverage`; a platform sensor is never named).
