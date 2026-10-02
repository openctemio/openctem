-- Performance indexes for new tables (attack_simulations, report_schedules, control_tests)
-- NOTE: Not using CONCURRENTLY because golang-migrate runs migrations in transactions.

CREATE INDEX IF NOT EXISTS idx_report_schedules_due
    ON report_schedules(next_run_at)
    WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_control_tests_linked_sims
    ON control_tests USING GIN (linked_simulation_ids);

CREATE INDEX IF NOT EXISTS idx_attack_simulations_config
    ON attack_simulations USING GIN (config);

CREATE INDEX IF NOT EXISTS idx_threat_actors_ttps
    ON threat_actors USING GIN (ttps);
