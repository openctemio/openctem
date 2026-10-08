### Added: a workflow's steps read as stages

- The workflow detail sheet and the New-scan preview show a workflow's steps
  as stages computed from its dependency graph, not as a flat numbered list:
  - parallel steps share a stage, labelled "N in parallel";
  - a step that waits for several shows "Waits for: X, Y";
  - each step reads capability first, then how it picks its tool (Any tool,
    Preferred list, Pinned tool).
- A summary gives the most steps that can run at once, set against the
  max-parallel limit, the longest chain, and an upper bound on duration from
  the step timeouts.
- Inline warnings cover:
  - a tool no online sensor offers;
  - a max-parallel limit lower than what the graph allows;
  - unpublished draft changes, when the caller passes them.
- A cycle or a dependency on a missing step is shown as a problem.
- A Stages / Graph toggle opens a read-only graph, with "Open in builder".
- One shared component (`WorkflowStages`), with en and vi strings. Run pages
  can colour its steps by run status.
