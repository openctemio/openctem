### Fixed: one organization's deep shared-sensor queue no longer starves the others

- A shared sensor's poll took the 1,000 oldest shared jobs before ranking organizations, so an organization with more old jobs than that (or one at its in-flight limit) kept every other organization's jobs off shared sensors. The poll now offers rounds of five jobs per organization, then orders by class, in-flight load, queue priority and age within a round. No migration.
