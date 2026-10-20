### Fixed: rolling back the severity override keeps the activity-type constraint validated

- The down of the analyst severity override migration re-added `finding_activities.chk_activity_type` as `NOT VALID`, so after a rollback to the previous release the constraint was not validated. It now validates it in the same step (only rows of the kept types remain at that point).
