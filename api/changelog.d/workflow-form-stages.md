### Changed: the workflow edit form shows stages and fixes old-format steps

- The Steps tab of the workflow form groups steps by stage, from what each
  step runs after ("Stage 2 · 2 steps run in parallel · waits for Stage 1"),
  numbers them 1, 2a, 2b and shows the steps of one stage side by side.
- Each step has a "Runs after" choice; a step that already waits for it is
  disabled (no loops). Dragging a step onto another stage moves it there by
  taking that stage's dependencies, and refuses a move that would make a loop.
- A step in the old format (a tool without its catalog capability) offers a
  one-click "Use capability ... (tool implements it)" fix that keeps the tool
  pinned; a banner fixes every such step at once.
- Step changes made in the form save to the workflow's draft and publish only
  through "Save and publish", like the builder: the version scans run is never
  changed in place. A workflow with a draft is edited from its draft.
- The New Scan starter cards summarize steps by stage ("DNS resolution + HTTP
  probe (in parallel)") instead of a flat chain.
