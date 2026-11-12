### Fixed: CTEM cycle writes never fail silently
- Scope refinement notes can be written on a cycle whose charter was never edited (it was stored as JSON null and the write failed). Charters are now always JSON objects; existing null charters become `{}`.
- The cycle description is stored and shown; an update that omits it keeps it.
- Activation and its scope snapshot are one transaction: a failed snapshot leaves the cycle in planning and the error is shown, instead of an active cycle with no snapshot.
- Closing is refused when the validation coverage check cannot run. A person may close anyway with a reason; the override is recorded in the audit log (`ctem_cycle.close_overridden`) before the close, and never lifts an enforced coverage SLO.
