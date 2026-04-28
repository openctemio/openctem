-- Rollback: clear inferred sub_types (cannot distinguish manual vs inferred)
UPDATE assets SET sub_type = NULL WHERE sub_type IS NOT NULL;
