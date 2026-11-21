-- Validate vuln_events_kind_check, re-added NOT VALID by advisory_cards (the
-- card event kinds). VALIDATE scans under SHARE UPDATE EXCLUSIVE in its own
-- migration (its own transaction): reads and writes go on meanwhile.
ALTER TABLE vuln_events VALIDATE CONSTRAINT vuln_events_kind_check;
