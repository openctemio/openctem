-- 001175 is a data correction: it voided "fixed" retest outcomes that could
-- not have matched. Re-resolving those findings would restore a false fix,
-- so the down migration deliberately changes nothing.
SELECT 1;
