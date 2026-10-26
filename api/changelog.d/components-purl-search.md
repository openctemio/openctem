### Added: find a package by pasting its package URL

- The Components search accepts a package URL such as `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. It matches that package exactly (not every package whose name contains the text), spelled the way the inventory stores it, and a version in it narrows the counts to the assets running that version. Plain text still searches names and namespaces. Counts stay limited to the assets you can see.
