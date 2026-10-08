### Changed: scan refusals and run messages say scan workflow and scan run, not pipeline

- Run refusals (scan workflow not found, disabled, without steps, a step without a scanner), run outcome messages and scan workflow audit messages now use the scan workflow / scan / scan run vocabulary. "Pipeline" is kept for CI pipelines.
- Error codes (`PIPELINE_*`) and the automation action `trigger_pipeline` are unchanged.
