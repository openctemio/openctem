### Behaviour change: unknown reachability is no longer read as unreachable

- A finding whose asset has unknown exposure and no attack path, threat path or scanner reachability flag (a dependency in a repository with no deployment data, for example) is now classified with reachability **unknown** instead of "not reachable". Its priority reason says so ("critical severity; reachability unknown …"), never "not reachable from attacker perspective".
- Exploitation evidence now raises such a finding to P1 even without reachability evidence: a CISA KEV CVE, EPSS of 50% or more, or EPSS of 10% or more on a critical or high asset. Before, these stayed at P2 because unknown counted as unreachable. A finding with only a high severity stays at P2 until reachability is known.
- An isolated asset still counts as unreachable; an internal-only asset (private or restricted) now names that in the reason.
- The finding drawer and page show a "Reachability unknown" risk signal, and every risk-signal label is translated.
- Existing findings take the new class and reason at the next reclassification sweep.
