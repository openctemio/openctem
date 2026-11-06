-- Self-service account deletion with a grace period (RFC-104). A row means
-- the person asked to delete their account: their sessions were ended at the
-- request, signing in again before erase_after cancels it, and after
-- erase_after the account's personal data is erased (the users row and its
-- foreign keys stay, shown as "Deleted user #<hash>"). New, empty table.
CREATE TABLE account_deletions (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    requested_at timestamp with time zone NOT NULL DEFAULT now(),
    erase_after timestamp with time zone NOT NULL,
    -- Set when the erasure takes the request: signing in no longer cancels.
    claimed_at timestamp with time zone
);

CREATE INDEX idx_account_deletions_erase_after ON account_deletions (erase_after);
