### Changed: the Possible duplicates queue follows the list pattern (redesign branch)

- A review is one line: the identity with its type, the reason, the evidence, the asset that stays and the assets
  that merge into it, with their counts. The two decisions (Merge, Keep separate) are buttons at the end of the row
  (the shared queue controls), shown to a user who may delete assets; the merge confirmation is unchanged. On a
  phone each review is a queue card with both decisions on its own row.
- The outcome of a decision is said to assistive technology as well as in the toast.
- Loading, a failed read (with Retry) and the empty queue are states of the table, so its toolbar stays; a user
  without access sees the shared no-access state.
- Every Needs attention queue says its count as the one list count beside its name.
- Docs: none (internal redesign branch)
