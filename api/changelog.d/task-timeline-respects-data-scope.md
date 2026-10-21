### Security: a task's timeline no longer shows other tasks the reader cannot open

- `GET /api/v1/remediation/tasks/{id}/timeline` hid nothing about the other task of a move, split or regression: its id, its title and the free-text move reason were shown even when none of that task's findings were in the reader's data scope. For a reader with a restricted data scope those fields are now removed from the entry (counts stay) and the entry carries `other_task_hidden: true`. Readers without a data scope are unaffected.
