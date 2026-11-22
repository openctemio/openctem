### Changed: the scan page uses the shared detail layout

- Scan page: the header shows the scan's state, type and intensity as chips, Run now as the main action, Edit and the schedule switch beside it, and Clone, Copy link, Copy scan ID and Delete scan in More (each still needs the same permission as before).
- Scan page: a facts strip shows the last run (it opens the run), the next run with its schedule and time zone, the run count with links to the successful, partly done and failed runs, and the success rate.
- Scan page: a run in progress shows above the tabs with Open run and Cancel run; the run history no longer repeats a Cancel button on its row.
- Scan page: Configuration and Details use the property list; the scan type and status are translated in Vietnamese.
- Scan page: the run history is requested once on load.
- Docs: none (layout of an existing page; same requests, permissions and API)
- The scan page's links to the findings and all runs sit under the runs table, and the scanner field in the scan dialog shows only the scanner name, so the sensor note no longer runs past the dialog on a phone. The e2e seed has a scan that never ran, which the request budget loads (a run in progress polls its list every 10 seconds).
