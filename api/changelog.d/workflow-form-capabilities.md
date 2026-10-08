### Fixed: the workflow form saves what a step does, not "scan"

- The scan workflow form is capability-first, like the builder: a step picks
  what it does ("DNS resolution", "Port scan") and runs on any tool, preferred
  tools or one pinned tool. Picking a tool instead gives the step the
  capability the tool implements (or asks when it implements several). The
  form used to save every step as `capabilities: ["scan"]`, so a DNSX step
  was refused ("capability 'scan' is not supported by tool 'dnsx'").
- Step capabilities accept both catalog keys (`resolve.dns`) and the older
  words (`dns`), mapped onto each other through the catalog. A refusal names
  the step, what the tool can run and how to fix it.
- Step keys are made from what the step does (`resolve-dns`, then
  `resolve-dns-2`), edited under "Advanced", and checked for format and
  uniqueness. Renaming a step never changes its key, and a key change moves
  the dependencies on it. Once a workflow has runs, the API refuses a change
  of a saved step's key: run history and data hops refer to it.
- Editing a workflow in the form sends its steps only when they changed, and
  then every field (id, tool preferences, retries, condition, settings,
  layout); the builder sends every field too.
- A step position from the builder canvas may be fractional or negative: it
  is stored rounded. A non-finite or out-of-range position is a 400, not a
  500 (`invalid input syntax for type integer`).
- New steps from an adapter suggestion run on any tool that implements the
  capability instead of pinning its default tool.
