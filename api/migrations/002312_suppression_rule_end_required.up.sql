-- Every suppression rule has an end. NOT VALID: new and updated rows are
-- checked at once; the next migration validates the existing rows without a
-- long lock.
ALTER TABLE suppression_rules
    ADD CONSTRAINT chk_suppression_rules_expires_at_set CHECK (expires_at IS NOT NULL) NOT VALID;
