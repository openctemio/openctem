### Fixed: the settings reachability e2e no longer times out on a cold server

- "every settings rail entry opens" loads one page per rail entry inside the default 60 s test budget, which a cold server exceeded once the rail grew (issue #3234). The budget now grows with the number of entries.
