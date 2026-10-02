-- Revert Migration 000228: drop user two-factor authentication state.
DROP TABLE IF EXISTS user_mfa_challenges;
DROP TABLE IF EXISTS user_mfa_recovery_codes;
DROP TABLE IF EXISTS user_mfa;
