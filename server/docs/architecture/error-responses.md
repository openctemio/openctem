# Error responses and status text a person reads

Every error body, and every stored status a read returns (an integration's
`status_message`, a step's or task's `error_message`), is read by a person:
in a toast, on a row, in a CI log. This page says what that text may hold and
how the code keeps it that way. The envelope itself is in
[api-conventions.md §10](api-conventions.md#10-errors-in-full-d2-d5).

## What a person sees

- The web picks the words from the `code` (`errors.<CODE>` in
  `web/src/lib/i18n/dictionaries/{en,vi}`), with the values in
  `details.params`, and adds the action that fixes it ("Add API token").
- The `message` is a safe English fallback for API clients, CI output and a
  code the web does not know yet.
- An unexpected failure (5xx) says what could not be done and shows
  "Reference" with the request id, which support finds in the server log.

## What never reaches a message

Entity ids (a UUID means nothing to a person; the page already names the
thing), SQL and driver errors (constraint and table names), dial, DNS and TLS
errors (internal hosts and ports), file paths, Go runtime and decoding text,
loopback or cluster host names and an upstream service's raw body. The
original error goes to the log with the request id.

The addresses and names of a tenant's own assets are not internal: "10.0.0.0/8
is outside the scope" stays as it is.

## How the code enforces it

1. **Cleaning at write time** (`pkg/apierror/safe.go`). Every response from
   `pkg/apierror` passes its message through `SafeMessage`: a message with
   technical text is replaced by the code's default message (the original is
   logged at WARN with `request_id`), UUIDs are cut out, the generic prefixes
   of the shared domain errors ("validation error: ") are dropped, and the
   length is capped. This is the last net, not the design.
2. **Codes first** (`pkg/apierror/codes.go`). New errors are
   `apierror.FromCode(apierror.CodeX)` with `WithParams(apierror.Params{...})`:
   the status and the default message come from the registry, and parameter
   values that look like ids or technical text are dropped. An unregistered
   code given to `FromCode` answers 500, so the gap is seen in review.
3. **The gate** (`tools/lint/errleak`, run in API CI). It fails on a function
   that gains one of: `err.Error()` or a formatted error in an `apierror`
   message (`echo`); an id formatted into an `apierror` message
   (`id-message`), into a sentinel-wrapped error a handler echoes (`wrap-id`)
   or into a domain error message (`domain-id`); a lower error's text inside a
   sentinel-wrapped error (`wrap-err`); a stored status built from an error's
   text (`status`); `err.Error()` in a raw JSON body (`raw-json`); an id in an
   audit event message (`audit-id`). Today's findings are a shrink-only
   baseline (`baseline.txt`): a PR that fixes a site lowers its line.
4. **Tests.** `pkg/apierror/safe_test.go` writes the leak samples found in the
   code (SQL, dial, DNS, paths, decode errors, upstream bodies, ids) through
   every constructor and checks the wire body.

## Stored status text

A failure recorded on a row is shown later in a 200 response, so it follows
the same rule: store a code and a safe sentence, log the cause. Reads pass
older rows through `SafeMessage`.

## Writing a message

"Could not <action> <object>." + why, if known + what to do. No ids, no
"Please", no blame. Name the object ("Jira SEC"), never its id.
