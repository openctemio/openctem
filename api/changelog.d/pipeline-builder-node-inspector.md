### Added: a settings panel for each step in the pipeline builder

- Clicking a step opens its settings: the capability (with its versioned id and tier), how it picks its tool (any tool, preferred tools in order, or one tool), the capability's standard settings, retries and timeout.
- The settings form is built from the capability contract served by `GET /api/v1/scans/stages`, so only the contract's settings can be entered. Values are checked as you type (types, allowed values, bounds, port lists), and the panel names the tools that cannot run the step with its settings.
- A step whose tool has no capability contract says so and keeps its own settings.
- The unused step edit panel is removed.
