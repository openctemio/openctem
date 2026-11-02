### Fixed: the console says why a sensor did not arrive on a pairing code

- When a sensor's attempt on a code made with **Create pairing code** is refused (its clock is off, it retried too often, another sensor already holds the code, or its key is busy or already registered), the waiting step now says so in plain words with the next step, instead of waiting with no explanation. Only the organization that made the code sees it; the sensor's answer is unchanged. Migration `20261031121231` adds the columns.

### Fixed: an approval the sensor never confirmed no longer leaves a sensor behind

- A sensor approved while it was stopped stayed in the list for ever, never connected. When its 10-minute confirmation window closes, the sensor (never used, no key, no jobs) is now removed and the removal is audited.
