### Changed: a column kind for a queue's decision buttons (redesign branch)

- Tables have a `decisions` column kind for a queue's Approve, Reject and More buttons: end-aligned, as wide as the page sets it, so every queue's last column lines up the same.
- The check that every table column declares a kind counts only table columns: a CSV export field list in the same file no longer counts as columns without a kind.
- Docs: web/docs/ui-style-contract.md (column kinds)
