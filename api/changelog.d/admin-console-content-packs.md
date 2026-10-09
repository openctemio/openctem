### Added: Console > System > Content packs

- Platform administrators list, upload (tar or tar.gz) and import (https URL pinned to a sha256) the
  content packs sensors run, see each pack's lint report (errors, suspected secrets, warnings and the
  files left out), copy the signing key, point the stable and canary channels at a pack and revoke one.
- Uploads, imports, channel moves and revokes ask for a reason and a fresh authenticator code (super
  admin only); a pack with suspected secrets is stored only after an explicit acknowledgement.
