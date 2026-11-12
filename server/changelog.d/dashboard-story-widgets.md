### Added: dashboard levers, weekly brief and KPI strip

- Three new dashboard widgets, computed into the dashboard snapshot on its refresh schedule (and by Refresh now), in the reader's scope:
  - **What would cut exposure most** (`exposure.levers`): up to three actions (fix the known-exploited findings, fix the P0-P1 findings past their SLA, apply the proposed remediation that clears the most risk, cover the assets with no successful scan), each with its exact effect on a measured figure and the list it opens.
  - **This week in brief** (`brief.weekly`): up to three fixed sentences from the snapshot with linked figures; no AI involved.
  - **Key figures** (`exposure.kpis`): P0-P1 open, known exploited, within SLA, median time to fix and discovery coverage in one strip.
- The Overview and CTEM templates lead with the levers, the exposure flow and the key figures, show the brief beside the attack paths and end with the Fix next table; the Executive template gains the three widgets. Earlier copies of these templates are offered the new widgets.
