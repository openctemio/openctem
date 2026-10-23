-- Removes the vulnerability id aliases. Findings keep the keys they have;
-- new reports key on the ids they name again.
DROP TABLE IF EXISTS vuln_id_aliases;
