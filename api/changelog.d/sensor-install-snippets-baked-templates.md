### Fixed: sensor install snippets keep the baked nuclei templates and a paired identity

- The docker run, Docker Compose and Kubernetes snippets on the Sensors page no longer mount empty directories over `/home/openctem`, `/scan`, `/cache` and `/config`. They hid the nuclei-templates release baked into the sensor image, so a sensor had no templates until its first download (and none at all on a host without internet access); under Docker those directories were not even writable by the sensor's user. Only `/tmp` is writable now, and `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` point the scanners' settings there.
- The Kubernetes snippet sets `fsGroupChangePolicy: OnRootMismatch`. With the default policy every pod start made the state volume's files group-readable, and the sensor refuses an identity key its group can read.
- The Helm snippet asks for chart 0.15.0 or later.
