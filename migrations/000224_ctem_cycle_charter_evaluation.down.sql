-- Revert Migration 000224: drop the CTEM cycle charter evaluation.
ALTER TABLE ctem_cycles DROP COLUMN IF EXISTS charter_evaluation;
