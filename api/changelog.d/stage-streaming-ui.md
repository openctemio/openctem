### Added: run page shows stage streaming, workflows can switch it off
- A stage lane on the run page shows **Streaming** while the stage still takes results from the stage before it, and **Streamed in N waves** after, with how much earlier it started than that stage finished when that is clear.
- Workflow settings gain **Wait for each stage to finish before the next starts** (`stage_barrier`).
