### Fixed: a retest the tool could not run is no longer reported as an unreachable target

- A sensor verdict of "unverifiable" (the tool could not run the check) was recorded as the reason `unreachable`, and the retest's run ended red as failed with code UNREACHABLE, which the console could not describe. It is now recorded as the reason `error` ("the tool could not run the check"), the run is shown as blocked with the code `RETEST_UNAVAILABLE` (its step skipped), and the finding stays as it is.
- The console describes the retest reason codes (UNREACHABLE, BLOCKED, AUTH_CHANGED, SERVER_ERROR, ENDPOINT_MISMATCH, NO_ENDPOINT_PROOF, TEMPLATE_CHANGED, NO_RESULT, ERROR, RETEST_UNAVAILABLE) in English and Vietnamese.
