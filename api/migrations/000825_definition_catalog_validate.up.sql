-- Validate the constraints 000820 and 000823 added NOT VALID, now that
-- 000822 and 000824 have filled the rows they check (RFC-044 §8 P1).
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
--
-- VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE: reads and writes go on
-- while it scans. A row written since 000820 already had to satisfy them.
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT fk_vulnerabilities_tenant;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_kind;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_namespace;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_lifecycle;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_origin;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_scope_tenant;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_origin_scope;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_merged;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_external_id;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT chk_vuln_cve_compat;
ALTER TABLE vulnerabilities VALIDATE CONSTRAINT fk_vulnerabilities_merged_into;
ALTER TABLE findings VALIDATE CONSTRAINT fk_findings_definition_link;
ALTER TABLE findings VALIDATE CONSTRAINT fk_findings_definition;
