### Fixed: a request reaching its timeout always gets the 504

- At the deadline the handler and the timeout path both saw the cancelled context, and a handler that wrote first answered its own status (200) instead of the 504. A write after the deadline is now refused when nothing was written yet, so the timeout response wins. Found as a flaky test on develop: 21 failures in 300 runs before, 0 after.
