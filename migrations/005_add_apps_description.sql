-- migrations/005_add_apps_description.sql
-- Add description column to apps table

ALTER TABLE apps ADD COLUMN IF NOT EXISTS description TEXT;

COMMENT ON COLUMN apps.description IS 'Application description';

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('005_add_apps_description');
