-- Rollback 000189: drop threat-model foundation tables in reverse dependency order.
DROP TABLE IF EXISTS technique_applicability;
DROP TABLE IF EXISTS attack_technique_mitigations;
DROP TABLE IF EXISTS threat_model_threats;
DROP TABLE IF EXISTS threat_models;
