### Changed: watchers are managed in one sheet, with undo

- The People section of a finding and of a remediation task no longer lists every watcher with a
  remove button next to each name, which removed a person on one tap. It shows one row (up to three
  avatars and "N watching") and your own Watch / Watching toggle. Tapping the row opens the manage
  sheet: watchers with why each one watches, a labelled Remove per row (for those allowed to remove
  others), Stop watching on your own row, and the add search. Removing and the toggle show an undo
  toast for 10 seconds; Undo adds the person back or flips your toggle back.
- Removing yourself is now always the stop (it sticks), never a delete that a later comment would undo.
- `GET .../participants` returns `added_by_name` per watcher (only while the adder is an active member
  of the organization) and `me.user_id` (the caller). Strings in English and Vietnamese.
