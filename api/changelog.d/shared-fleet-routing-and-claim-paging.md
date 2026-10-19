### Fixed: routing auto uses the shared fleet, and withheld jobs no longer block a sensor's claim

- A run step under routing `auto` now goes to the shared sensors when no sensor of the organization can run the tool and the organization may use shared sensors. Before, it was always queued for the organization's own sensors, so an organization without one waited until the run timed out.
- The run page's "Why waiting?" says whether the shared sensors were an option for a task none of the organization's sensors can take (`shared_fleet`: `not_used` or `not_allowed`).
- A claim whose first candidate page is entirely withheld by the checks after the query (grant, local policy, scope re-check, scan windows, program rules, tool settings) reads the next page without them, up to three pages, for organization and shared sensors. The free-slot cap now applies last. New metric `command_claim_pages_total{mode}`.
- Shared sensors: within a round, the organization with the fewest shared jobs in flight now comes before the priority class, so one organization's aged jobs no longer outrank another's fresh job. One verification (critical) job per organization and round may jump that order.
