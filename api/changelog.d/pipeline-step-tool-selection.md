### Added: pipeline steps pick their tool by capability (auto, prefer, pin)

- A pipeline step names a capability and picks its tool in one of three ways. **auto** takes any implementation, with the catalog default first. **prefer** (`prefer_tools`) tries an ordered list. **pin** (`tool`) runs one tool only. Each tool in a prefer list must implement the step's capability, and a step cannot both pin a tool and list tools to prefer. Migration 001162 adds `pipeline_steps.prefer_tools`.
- Step settings follow the capability contract. Standard params are checked against their type, allowed values and bounds on every save, and each tool receives them under its own config key (for example naabu's `top_ports` for `top_n`). A tool that does not take a param the step sets is skipped, with the reason, so the value is never dropped silently. A pinned tool's own settings go under `x.<tool>`, or as plain keys on a pinned step.
- A queued step run records the capability it ran (`step_runs.capability`, for example `scan.ports@1`) and the tool the planner picked.
- The API adds `prefer_tools` and `tool_selection` on steps, and `capability` on step runs.
