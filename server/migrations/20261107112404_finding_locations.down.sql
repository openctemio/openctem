-- Removes the location tables. The timeline entry type stays allowed (rows may
-- use it). Revert the location merge first (cmd/vulnmatch-locations -down):
-- dropping its journal makes the merge permanent.

DROP TABLE IF EXISTS finding_location_merges;
DROP TABLE IF EXISTS finding_locations;
