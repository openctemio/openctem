### Fixed: saving threat-alert organization state no longer fails when the organization is deleted at the same moment

- The state row is now written under a key-share lock on the organization, so a concurrent delete waits instead of raising a foreign-key error.
