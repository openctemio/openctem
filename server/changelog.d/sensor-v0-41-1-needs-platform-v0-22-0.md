### Changed: sensor v0.41.1 and later need platform v0.22.0

- The versions manifest (`openctem-versions.json`) and the documentation's compatibility table now say that sensor releases from v0.41.1 on need platform v0.22.0 or later: such a sensor with a local `ports.allow` refuses a port scan that names no ports, and v0.22.0 is the first platform that fills those ports from the sensor's list. v0.22.0 is also proven to sign every command type (a v0.41.1 sensor that pinned the job signer refuses unsigned jobs), and it refuses late results of a run it took back.
- **Upgrade note:** upgrade the platform to v0.22.0 first, then sensors to v0.41.1 (sdk-go v0.51.0). Sensors from v0.36.0 (the oldest v0.22.0 accepts) to v0.41.0 keep working with v0.22.0.
- Docs: server/docs/architecture/versions-manifest.md
