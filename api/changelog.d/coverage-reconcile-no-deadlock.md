### Fixed: the coverage ledger no longer deadlocks with asset updates

- Inserting a ledger row takes a key-share lock on its asset (the foreign
  key). The coverage reconcile took those locks in arbitrary order in one
  statement per rule, while the asset business-context update locks the
  same assets `FOR UPDATE` in id order: the two deadlocked on live. The
  reconcile now reads assets in batches of 500 in id order (keyset, one
  short statement each, no wide transaction), inserts only missing rows in
  id order, and retries a statement once after a short jitter if PostgreSQL
  still reports a deadlock. The foreign key stays.
