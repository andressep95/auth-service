-- Migration 004: Cleanup Unused Tables
-- Description: Removes unused tables that were created but never implemented
-- Date: 2024-12-07

-- These tables were created in initial migration but never used in the codebase
-- The functionality was implemented using fields directly in the users table:
-- - email_verification_token (instead of email_verifications table)
-- - password_reset_token (instead of password_resets table)

-- Drop unused email_verifications table
DROP TABLE IF EXISTS email_verifications CASCADE;

-- Drop unused password_resets table
DROP TABLE IF EXISTS password_resets CASCADE;

-- Note: All existing functionality remains intact
-- Email verification and password reset still work using the fields in users table
