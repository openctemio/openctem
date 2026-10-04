-- Removes the catalog row the up migration added (by its fixed id).
DELETE FROM tools WHERE id = '00000000-0000-0000-0000-000000000495';
