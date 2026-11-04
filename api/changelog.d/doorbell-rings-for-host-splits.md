### Fixed: an idle sensor is told about work its claim would split

- The heartbeat doorbell counted only tasks whose hosts were all free. A run-step task waiting for a few hosts another task held is split by the next claim (its free targets start at once), but the doorbell said `pending_jobs=0`, so an idle sensor took that work only on its five-minute safety poll. When nothing else is ready and the sensor has a free slot, the doorbell now also counts the tasks its next claim would split (read-only, the same plan the claim applies, within the sensor's own organization).
