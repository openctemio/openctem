### Changed: Dashboard templates follow one set of layout rules

- Every template opens on its headline figures, then its hero visual, what to act on, trends and breakdowns; rows are full and of one height, at most ten widgets, and no two widgets show the same figures. A test checks every template against these rules.
- New Attack surface template (discovery coverage, posture, attack paths, fix next, new assets, certificate expiry). The Overview template is removed: it repeated CTEM; existing copies keep working.
- CTEM drops the weekly brief and intake (the levers and the exposure flow already carry them); Executive drops the levers and adds attack paths and campaign progress; Triage adds open findings by age; Vulnerability program drops open findings by SLA state.
- Short bar lists take one row instead of two, so they no longer stretch into blank space.
- A narrow widget with no data keeps its row height instead of leaving a hole beside its neighbour.
- Stored dashboards are not changed: copies of a template are offered the new layout (keep or switch).
