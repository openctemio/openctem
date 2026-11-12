-- Drops the exploration layer (leads, links, verdicts). The records it
-- referenced (assets, findings, runs) are untouched.
DROP TABLE IF EXISTS exploration_verdicts;
DROP FUNCTION IF EXISTS exploration_verdicts_append_only();
DROP TABLE IF EXISTS exploration_links;
DROP TABLE IF EXISTS exploration_leads;
DROP TABLE IF EXISTS explorations;
