# Findings triage mode

Triage mode decides the findings of one list query one at a time, from the
keyboard. The findings list opens it from its primary button, **Triage** (or
the `t` key), on the Needs triage queue: findings in status `new`, in the
list's default priority order. The route takes any list query, so the same
mode works on another view (for example `status=in_review` for a pentest
peer review).

Status: shipped (web). No API endpoint of its own.

## Route and queue

```
/findings/triage?<findings list query>       findings:read + findings:status (route guard)
```

- The query is the findings list API query (`GET /api/v1/findings`) without
  paging. Param names that are not lower snake case are dropped, never
  forwarded.
- The queue is read in windows of 25 through that same list API, so the
  server applies the caller's tenant and data scope on every window. A
  finding outside the caller's scope can never enter the queue.
- Decided findings leave a `status=new` view, so the server's pages shift.
  The next window is read from where the seen findings that still match end
  (skipped, assigned and requested findings stay in the view), and ids
  already in the queue are dropped.
- The tab keeps `{query, return path, ordered ids, outcome per id, position}`
  in sessionStorage under one key, so a reload resumes the session. Stored
  values are validated on read: a malformed session reads as none, ids must
  be UUID-shaped, and the return path may only be `/findings` or
  `/findings?...` (anything else, including another origin, a
  protocol-relative URL or a backslash, becomes `/findings`). Exit can never
  be turned into an open redirect.
- Moving to the next finding costs one read (`GET /findings/{id}`), plus a
  window every 25 findings (and the AI triage read, when that card is on).

## Decisions

Every key is also a visible, labelled button in the decision region. Each
decision calls the endpoint the finding page calls, with the shown
`row_version` as `If-Match` ([finding row version](finding-row-version.md)).

| Key | Action | Endpoint and rule |
|---|---|---|
| `c` | Confirm | `GET /findings/{id}/transitions` first (a blocked move shows its reason; a move the organization's lifecycle gives a note or fields opens the lifecycle dialog), then `PATCH /findings/{id}/status`. `findings:status` |
| `f` | Request false positive | The approval dialog: reason and note required, `POST /findings/{id}/approvals`. The organization's false-positive level decides whether a second approver is needed |
| `a` | Request risk acceptance | The approval dialog with an end date, `POST /findings/{id}/approvals`. Four-eyes unless the organization allows one approver |
| `o` | Assign | The assignee picker (members who can read the finding), `POST /findings/{id}/assign`. `findings:assign` |
| `m` | Add to task | The add-to-task dialog (new or open task); a finding already in an active task answers 409 with its task, and the dialog offers the audited move. Remediation module and task permission |
| `r` | Retest | `POST /findings/{id}/retests` (a deterministic re-check of the finding's rule). `findings:verify` |
| `s` | Skip | Nothing written |
| `u` | Undo last | Up to 10 decisions, newest first, each through its inverse request (below) |
| `j` / `k` | Next / previous | Nothing written |
| `e` | Evidence | Loads the finding's evidence items (masked; reveal keeps its permission, rate limit, step-up and audit) |
| `Enter` | Full page | `/findings/{id}` |
| `?` | All keys | |
| `Esc` | Exit | Back to the list the session started from, with its filters |

- A decision moves on to the next undecided finding by itself.
- Undo walks a decision back through the inverse request, which the server
  checks like any other: a sent false-positive or acceptance request is
  canceled (`POST /approvals/{id}/cancel`, kept on record, never deleted), an
  assignment goes back to the previous assignee, a skip is simply revisited,
  and a status moves back only where the lifecycle allows it. A decision
  with no inverse (a confirm: the lifecycle has no confirmed to new move, an
  added task, a started retest) says so and leaves the Undo stack. Undo
  writes on the finding's current version, read just before.
- Exit after decisions shows the session's receipt (counts and the outcome
  of each finding) before going back to the list.
- The finding's latest AI triage shows as an advisory card (only with the
  AI triage module and `ai_triage:read`, one more read per finding). When it
  suggests a false positive, "Apply suggestion" opens the false-positive
  request with the model's reason as the note; the person picks the reason,
  edits and sends it. AI never writes.
- A write answered 412 (someone changed the finding since it was shown)
  reloads the finding and stays on it; nothing is overwritten.
- A finding whose status changed after its window was read, or that is no
  longer readable (404), is passed over with a note on the way forward and
  shown with the note on the way back.
- Findings people reported (`source` pentest, bug_bounty, red_team or
  manual) are decided in their own workflow: the decision buttons are off,
  as in the finding drawer.
- Buttons and keys follow the caller's permissions (`findings:status`,
  `POST /findings/{id}/approvals`, `findings:assign`); the server checks
  them again on every write.
- Closing moves that need step-up use the shared re-authentication dialog
  once per step-up window; the session continues after it.

## Keys and input safety

Keys are ignored while focus is in a field, a picker, a menu or a dialog,
while any dialog is open, with a modifier held, and on auto-repeat. A letter
typed into a note can never become a decision. Enter on a focused button
presses that button.

## Threat model

| Threat | Control | Test |
|---|---|---|
| Out-of-scope or cross-tenant finding in the queue | Windows come from the list API with server-side scope; no ids are trusted from the client | `triage-mode.test.tsx` (queue from the list API), Playwright on a seeded stack |
| Four-eyes bypass through triage | False positive and acceptance are approval requests, never status writes | `triage-mode.test.tsx` "f opens the false positive request" |
| Lost update (a decision on stale facts) | `If-Match` row version, 412 reloads | `triage-mode.test.tsx` "a stale write (412)" |
| Open redirect through a crafted session | Return path limited to `/findings?...` | `triage-session.test.ts` "safeReturnPath" |
| Keys acting while typing, or under a dialog | Key filter on focus and open dialogs | `triage-keys.test.ts` |
| AI deciding for a person | The AI card only prefills the request form | `triage-mode.test.tsx` "the AI suggestion only fills the request form" |
| Undo as a bypass (deleting a request, resetting a status) | Undo uses inverse requests with their own server checks; requests are canceled, not deleted | `triage-mode.test.tsx` undo cases, Playwright (canceled row) |

Design: research note 234 §5.2 (internal).
