### Security: a stopped run no longer closes findings or marks branch occurrences fixed

- A completed scan whose result says the run stopped (a non-zero exit code such as -1 from a scanner killed by the job budget, a status other than completed, a sensor stop or failure, or an unreadable result) now proves nothing. Older sensors deliver such a run as "completed" with full coverage and every target done.
- Guarded paths: coverage auto-resolve (new reason `run_stopped`), the per-branch occurrence sweep (v1 and v2), per-target coverage settlement, the wildcard DNS mark, the collector's full-coverage check, and both retest methods (a fixed or not-reproduced verdict from a stopped run is inconclusive; a match still stands).
- The v2 per-branch sweep of a report bound to a command now runs once per run, after the command completed by itself and every report completed. Two reports of one run on the same branch and tool sweep nothing.
- A crashed run's finished targets count as unfinished and are scanned again.
