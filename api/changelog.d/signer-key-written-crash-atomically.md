### Fixed: the signing key is written crash-atomically

- The signer now writes a new key to a temp file in the same directory,
  syncs it and links it into place, so a kill or crash during first-start
  generation can no longer leave a partial key file that the next start
  treats as the real key. Stale temp files from a crashed run are cleaned.
- A truncated or corrupt key file now fails to load with a clear error that
  says to restore it from the offline backup. It is never regenerated, since
  a new key would change the signing identity.
