### Security: the producer's keyed secret hash is no longer stored or returned on a finding

- The keyed hash of a raw secret that a CI job sends as `secretHMAC/v1` identifies the finding at ingest and is then dropped: it is not saved in `partial_fingerprints`, and `GET /api/v1/findings/{id}` never returns it (also for findings saved earlier). Before, anyone who could read a finding and run a CI job on the repository could use it, with the job's key, to confirm a short secret offline.
- The finding keeps its tenant-keyed fingerprint (`secret_fingerprint`), which cannot be checked without the server secret.
