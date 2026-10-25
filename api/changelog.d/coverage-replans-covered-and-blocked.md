### Fixed: continuous coverage runs again after each cadence and rechecks blocked pairs

- The coverage planner only picked `due` and `failed` pairs, so a pair that was covered once was never planned again and a pair the scope gate refused was never rechecked. It now also picks `covered` pairs whose cadence has elapsed and `blocked` pairs whose 6 h recheck time has passed. A scope entry added later, a sensor installed later or a guardrail lifted later now takes effect without a person.
- Due times carry a fixed 0 to 10 % jitter per asset and capability, so cadence waves spread out and a restart does not start everything in the same minute. A batch also takes pairs due within a tenth of the cadence (at most an hour) when one pair is due now.
- A blocked pair whose precondition stops holding becomes `not_applicable`.
- Migration `003413_asset_coverage_plannable_index` replaces the planner's partial index. Upgrade note: after the upgrade the planner catches up once on pairs past their cadence (on a typical installation a few hundred), within the daily coverage budget.
