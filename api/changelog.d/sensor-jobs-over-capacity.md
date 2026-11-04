### Fixed: the sensor jobs card no longer shows more jobs running than its capacity without saying why

- A sensor sizes its job slots from the CPU and memory free on its host, so its capacity can drop below the jobs it already runs when the host gets busier. The sensor detail card, the Jobs tab, the sensors table and the phone card showed that as a bare "2 / 1, 0 slots free". They now say "Over capacity by 1, no new jobs" (warning tone, with the reason on hover), and the meter no longer runs past its end.
- The free slots shown are the platform's own dispatch figure (`available_slots`: capacity minus the jobs the platform counts as held, a fresh load report's free slots and host pressure), so the console and placement never disagree; "host busy" is shown when host pressure is what narrows them.
- No API, migration or sensor change is needed; older sensors and older APIs (no `available_slots`) fall back to capacity minus running.
