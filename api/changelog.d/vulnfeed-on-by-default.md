### Changed: vulnerability bundles import with no setup

- The platform pins the root key id of the official vulnerability bundles (first key ceremony of openctemio/vulnfeed, 2026-10-25), and the `vulnfeed` source is now on by default. Inventory matching and emerging-vulnerability alerts start working after the next sync, with no environment variable and no admin step. `VULNFEED_ROOT_KEY_ID` still overrides the root for a private collector; a platform admin can still switch the source off.
