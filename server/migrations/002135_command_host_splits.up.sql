-- How often a pending command was split at claim time because some of its
-- hosts were busy (pkg/domain/command/host_split.go): the split is bounded
-- by command.MaxHostSplits. A constant default: no table rewrite.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS host_splits smallint NOT NULL DEFAULT 0;
