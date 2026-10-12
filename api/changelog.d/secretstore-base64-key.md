### Fixed: a base64 APP_ENCRYPTION_KEY no longer stops the API at start-up

- Configuration accepts `APP_ENCRYPTION_KEY` as 64 hex, 44 base64 or 32 raw
  characters, but the secret store decoded only hex and used a base64 key as its
  44 raw bytes, so the API exited with "encryption key must be 32 bytes". The
  Helm chart generates a base64 key, so a default chart install never started.
  The secret store (and `rekey`) now decode the key the same way configuration
  validation does.
