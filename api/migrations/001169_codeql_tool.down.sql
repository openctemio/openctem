-- Removes the codeql row this migration added (a pre-existing row is kept).
DELETE FROM tools WHERE id = '00000000-0000-0000-0000-000000000131';
