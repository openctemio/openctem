-- Data correction: a notification dated in the future never reads as read
-- (the unread count compares its time with the user's read-all watermark).
-- Set any row more than a minute ahead of the database clock to now. Touches
-- only such rows (a handful on a live install); no schema change.
UPDATE notifications SET created_at = NOW() WHERE created_at > NOW() + INTERVAL '1 minute';
