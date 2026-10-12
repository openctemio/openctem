### Added: sensor grant view, narrowing and trust level in the console (RFC-052)

- The sensor detail has a **Grant** panel: profile, trust level, job types, zones, tools, capabilities, tier ceiling, target network and scope, credentials, results without a job and remote actions, with what applies now while the sensor is New. A list with no limit reads "Any", an empty one "None".
- **Promote to Trusted** (needs `sensors:grant:widen`, confirmed with what New means) and **Set back to New** (`sensors:grant:narrow`).
- **Edit / Narrow**: apply a profile or edit dimensions one by one. The form warns when a change widens the grant; the server decides and its refusal is shown as is. A grant changed by someone else in the meantime is reloaded.
- The sensor list flags **Legacy broad grant** (narrow it) and **New**.
