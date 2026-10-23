### Fixed: the finding page tells "not found" from "could not load"

- A server or network error on the finding page now shows "Could not load this finding" with a Retry button; only a missing or refused finding shows "Finding not found" (same copy for both, so it reveals nothing about what exists).
- A bad link costs one request instead of three and no longer pops a raw error toast.
- The remediation task band, ticket links and retest check show an error row with Retry when their read fails, instead of looking empty.
