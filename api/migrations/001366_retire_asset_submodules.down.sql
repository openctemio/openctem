-- No-op: the assets.* sub-modules gated pages that no longer exist, and the
-- tenant overrides deleted with them toggled nothing. Restoring the rows
-- would bring back dead settings toggles.
SELECT 1;
