-- Rollback 000190: remove the attack-16.1 seed rows (leaves the tables in place;
-- schema is owned by migration 000189).
DELETE FROM technique_applicability      WHERE dataset_version = 'attack-16.1';
DELETE FROM attack_technique_mitigations WHERE dataset_version = 'attack-16.1';
