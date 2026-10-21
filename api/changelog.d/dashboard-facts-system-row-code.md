### Fixed: the dashboard facts system-row fix now ships its code

- The earlier entry "dashboard facts no longer try to build the platform's system row" landed without its query change, so the error kept appearing every minute. The pending-runs query now skips the all-zero system tenant, with a database test.
