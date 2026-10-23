### Fixed: Insights and Reports share one period and number format
- Program health sends its period to the executive summary, so every card follows the selector.
- The executive summary, Program health and Reports use one set of periods (30 days, 90 days, 1 year) and one percent and risk format.
- A failed read on these pages shows an error with Retry instead of "No data yet" or dashes.
- Owner coverage has one definition and target (95%) on Program health and Data quality.
- The Program health chart plots the same series as the figure, with locale dates and a screen-reader table.
- Download CSV on Reports is shown only to people who can read the dashboard.
- The internal "From:" and "Source:" lines are gone from the scorecards.
- The Insights pages are translated (English and Vietnamese).
- Removed the redirect-only `/insights/reports/compliance` and `/insights/reports/scheduled` routes.
