### Behaviour change: the Sensors page lists sensors only; CI pipelines live on CI/CD

- The Sensors page no longer has the All / Daemon / Runner switch, the "CI pipelines fresh" metric or CI pipeline rows, and its "Needs attention" counts sensors only. CI pipelines, their runs and coverage are on the CI/CD page alone.
- When the organization has active CI pipelines and the caller may read them, Sensors shows one line, "N CI pipelines report through CI/CD", with the number of failing gates linking to that filter.
- With no sensor yet, Sensors explains what a sensor is. It offers "Pair a sensor" first, and "Install with an API key" where the organization allows bearer keys. It also notes that scanning repositories from CI needs no sensor.
- Old links to `/sensors?mode=runner` (and an open pipeline, `&pipeline=<id>`) now go to the same view on CI/CD.
