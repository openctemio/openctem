DELETE FROM platform_settings WHERE source = 'migration';

ALTER TABLE platform_settings DROP CONSTRAINT chk_platform_settings_source;
ALTER TABLE platform_settings ADD CONSTRAINT chk_platform_settings_source
    CHECK (source IN ('environment', 'console'));
