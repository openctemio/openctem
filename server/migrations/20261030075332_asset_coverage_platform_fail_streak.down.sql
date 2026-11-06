-- The moved streaks go back into fail_streak before the column goes.
UPDATE asset_coverage
SET fail_streak = least(fail_streak + platform_fail_streak, 32767)
WHERE platform_fail_streak > 0;

ALTER TABLE asset_coverage DROP CONSTRAINT IF EXISTS chk_asset_coverage_platform_fail_streak;
ALTER TABLE asset_coverage DROP COLUMN IF EXISTS platform_fail_streak;
