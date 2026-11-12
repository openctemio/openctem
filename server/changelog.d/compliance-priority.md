### Behaviour change: compliance findings take their priority from the benchmark level

- A benchmark check that failed no longer takes the scanner's severity (a Nessus CIS FAILED arrived as High, then P2 with a 15-day window). Its severity comes from the benchmark level (level 1 or unknown: medium; level 2 or 3: low; a warning: low), raised one band on a crown jewel, a critical asset or in production; its class is P2 for high, P3 otherwise, never P0 or P1 by itself. Exploitation signals never apply to a benchmark check; a tenant priority rule may still raise one.
- The scanner's severity is kept on the control's check state and in the sighting's source data.
- New findings filter `compliance_level` (lists, saved views, export); the check result and level filters have labels in the picker.
- **Upgrade note:** findings stored before this change keep their severity until the `compliance-checks` command re-classifies them (dry run by default).
