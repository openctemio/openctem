### Fixed: a role or team change applies without signing in again

- After a role or team change, the console renews its session as soon as any answer says the permissions changed, so the next write goes through instead of being refused until the next sign-in. Renewals are at most one per 10 seconds.
