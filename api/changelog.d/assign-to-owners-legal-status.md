### Fixed: "Assign to owners" skips closed findings and changes status only along the lifecycle

- `POST /api/v1/findings/actions/assign-to-owners` assigned resolved, false
  positive and accepted findings to their asset owners. Closed findings are now
  left alone.
- It tried to move a `new` finding straight to `in_progress`, which is not a
  lifecycle edge (the error was dropped). A `new` finding is now assigned and
  stays `new`; a `confirmed` finding moves to `in_progress`. The response
  reports how many started (`started`).
