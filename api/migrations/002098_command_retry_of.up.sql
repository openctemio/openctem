-- A scan command that completed with unfinished targets is followed by a new
-- command carrying only those targets (research/125); retry_of names the
-- command it continues, so the task timeline shows the chain.
--
-- Live impact: one nullable column, no default, no rewrite, no backfill.

ALTER TABLE commands ADD COLUMN retry_of UUID;
