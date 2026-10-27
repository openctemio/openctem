### Changed: the merge queue skips tests for a tree that already passed

- A merge-queue group whose git tree equals the tree a pull request (or an earlier queue or push run) already passed every required check on skips the heavy jobs; the required checks still report success, with the verified tree and commit in their log. Any difference runs the normal tier.
