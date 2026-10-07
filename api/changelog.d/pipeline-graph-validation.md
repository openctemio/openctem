### Behaviour change: a pipeline save validates its workflow graph

- Saving a pipeline (create, full save, or adding, editing or deleting a step) now checks the steps as a graph against the scan capability contracts. Before, an edge between incompatible steps (for example subfinder → katana: hostnames into a URL crawler), a cycle or a dependency on a missing step was stored, and the run silently fed the step the scan's own targets instead.
- A refused save returns `422 VALIDATION_FAILED`. Every problem is anchored to a step or a connection in `details.errors`, and an incompatible connection names the capability that would connect it ("insert HTTP probe"). A connection to or from a tool without a contract (a tenant tool) is a warning: it orders the steps and passes no data.
- `POST /api/v1/pipelines/validate` (`pipelines:write`) checks a draft and stores nothing.
- Deleting a step removes it from the other steps' dependencies. Every seeded system template passes the check.
- **Upgrade note:** an existing pipeline whose graph is invalid keeps running as before, but it must be fixed before its next save.
