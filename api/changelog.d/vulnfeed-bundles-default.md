### Changed: the vulnerability feed is read from openctemio/vulnfeed-bundles

- The default `VULNFEED_BASE_URL` is now `https://github.com/openctemio/vulnfeed-bundles/releases`: the signed feed moved to its own repository, separate from the collector code (openctemio/vulnfeed). The pinned root key and the bundle format are unchanged, so a platform needs no other change. Until 30 days after this release the old location keeps a verified copy of the feed, so a platform that sets `VULNFEED_BASE_URL` to it, or runs an older version, still imports.
- An air-gapped mirror or an explicit `VULNFEED_BASE_URL` is used as before. Firewalls that allow `github.com` need no change (the host is the same).
