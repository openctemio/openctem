### Changed: one flow view for a scan run

- The run drawer draws the run's steps as one flow. Each step is a card
  with its state (colour, icon and label), tool, chunk progress bar, outputs,
  findings, duration and the comparison with the last run; text wraps instead
  of being cut. Steps that run side by side are drawn as a laid-out graph
  (left to right or top to bottom, whichever fits) with arrows labelled with
  what flowed along them; a chain of steps, and a phone screen, get the list.
  The separate Stages/Graph toggle of the run map is gone.
- A skipped step says which upstream step it waited on ("Skipped: HTTP probe
  failed").
- A finished step whose targets the sensor's network confinement refused says
  "could not reach N targets (blocked by the sensor's network confinement)"
  instead of "produced nothing", when the API reports
  `egress_refused_targets` on the step's tasks.
- Every step card is a button: click or Enter opens the step's panel (tasks,
  logs, outputs). The run drawer is wider (2xl) to fit three steps side by
  side.
