### Fixed

- A path exclusion no longer stops every POST, PUT, PATCH or DELETE request of a web scan on the whole host. A job whose web scope only denies paths now lists every method; the sensor read an empty list as GET, HEAD and OPTIONS only, so nuclei's POST templates were refused everywhere and nuclei skipped the host as unresponsive (`breaker_open`).
