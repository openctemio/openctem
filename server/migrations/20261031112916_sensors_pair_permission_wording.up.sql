-- The console calls reverse pairing "Create a pairing code first"; the
-- permission description shown on the roles pages follows it (RFC-052).
UPDATE permissions
   SET description = 'Look up a pairing code, create a pairing code for a new sensor and deny pairing requests'
 WHERE id = 'sensors:pair';
