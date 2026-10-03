-- Remove only the still-pending reviews this migration queued.
DELETE FROM asset_dedup_review
WHERE status = 'pending'
  AND reason IN ('normalization_garbled', 'normalization_rename', 'normalization_truncated_arn');
