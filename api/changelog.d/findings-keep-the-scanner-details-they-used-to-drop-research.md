### Changed: Findings keep the scanner details they used to drop (research 17 R2)

- Ingest now stores the rule **family** (Nessus / Tenable.sc plugin family,
  scanner category), the scanner's **exploit-available** verdict as a column,
  **VPR** (display only, no priority effect), the **CVSS version**, **every
  CVE** named on the finding (`cve_ids`) and the vendor **patch publication
  date**. The finding API returns them. Migrations 000688-000689 (nullable
  columns, NOT VALID checks, partial indexes, and a backfill of the exploit
  flag from metadata). Fingerprints are unchanged.
