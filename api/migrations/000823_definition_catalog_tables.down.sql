ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_definition;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_definition_link;
ALTER TABLE findings DROP COLUMN IF EXISTS definition_id;

DROP TABLE IF EXISTS finding_definitions;
DROP TABLE IF EXISTS definition_taxonomy;
DROP TABLE IF EXISTS taxonomy_entries;
DROP TABLE IF EXISTS definition_relations;
DROP TABLE IF EXISTS definition_identifiers;

ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS fk_vulnerabilities_merged_into;
