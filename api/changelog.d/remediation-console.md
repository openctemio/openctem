### Added: the Remediation console (fix plan, suggestions inbox, tasks, task detail)

- Remediation now opens on a **Fix plan** (tasks and suggestions ranked by risk left), with **Suggestions**
  (review inbox with "why" explanations, keyboard review and bulk accept), **Tasks** (saved views, table or board)
  and **Campaigns** (the former Remediation page, now at `/remediation/campaigns`).
- The task page shows the fix steps to copy, progress, the findings grouped by asset (a windowed list that stays
  fast with thousands of findings), and lets a person move findings (palette with compatibility warnings or drag
  and drop, with undo), split, mark the task fixed, hold or cancel it, and read its timeline.
- **Behaviour change:** campaign pages moved from `/remediation` and `/remediation/{id}` to
  `/remediation/campaigns` and `/remediation/campaigns/{id}`; old links are not redirected.
- The API's 409 answers for a finding already in another task and for a move that needs confirmation also carry
  `details.finding_ids` / `details.warnings`.
