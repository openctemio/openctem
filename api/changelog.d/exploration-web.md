### Added: Exploration page and asset Next steps (web)

- Discovery has an **Exploration** page (`/exploration`, `assets:read`, module Scans). It opens with
  one status sentence from the precomputed figures (next steps, waiting for approval, last step) and
  Refresh now for organization-wide figures, then one list grouped as Waiting for you, Next, Running
  and Done recently, with keyset paging. Each row says what is checked, on which asset, why, how
  intrusive the step is and how it ranks; a drawer shows the rationale, links, answers (heuristic and
  AI answers are labelled as unverified), the score inputs and why a step is blocked.
- People with `scans:approve` approve (with step-up) or dismiss waiting steps one by one or in bulk;
  each step is answered on its own.
- The asset page and drawer show **Next steps**: up to three steps on the asset with their state,
  See all (the Exploration page for that asset) and Ask (`scans:execute`), which asks a catalog
  question about the asset.
- The audit log labels the exploration actions (`exploration.lead_opened`, `lead_approved`,
  `lead_dismissed`, `lead_state_changed`, `lead_verdict`).
