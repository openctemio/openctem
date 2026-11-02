### Fixed: a duplicate index on organization wordlists is dropped

- The wordlists table carried two indexes on the same columns (the unique name constraint already serves lookups). Migration 20261031051532 drops the extra one, which also keeps the duplicate-index check green.
