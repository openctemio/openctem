-- Only for a full revert after a per-tenant restore (runbook F4): the journal
-- is the only record of what an apply changed, so never drop it while items
-- with outcome 'applied' exist.
DROP TABLE IF EXISTS provider_address_move_items;
DROP TABLE IF EXISTS provider_address_moves;
