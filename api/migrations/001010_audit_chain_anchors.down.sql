-- Without the anchors a pruned chain looks broken at its first remaining
-- entry (its prev_hash has no known predecessor); the JSONL archives still
-- hold the pruned rows.
DROP TABLE IF EXISTS audit_chain_anchors;
