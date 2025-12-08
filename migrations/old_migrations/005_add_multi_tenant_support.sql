-- Migration 005: Add Multi-Tenant Support
-- Description: Converts the system to support multiple apps (realms) with isolated users
-- Created: 2024-12-07
-- Breaking Change: Users are now scoped to apps (email unique per app, not globally)

-- ============================================================================
-- PART 1: Add app_id to users table
-- ============================================================================

-- Step 1: Add app_id column as nullable first
ALTER TABLE users
ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE CASCADE;

-- Step 2: Migrate existing users to base app
-- All existing users belong to the base app (7057e69d-818b-45db-b39b-9d1c84aca142)
UPDATE users
SET app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
WHERE app_id IS NULL;

-- Step 3: Make app_id NOT NULL now that all rows have values
ALTER TABLE users
ALTER COLUMN app_id SET NOT NULL;

-- Step 4: Create index for app_id (critical for performance)
CREATE INDEX idx_users_app_id ON users(app_id);

-- ============================================================================
-- PART 2: Change email uniqueness constraint
-- ============================================================================

-- Step 5: Drop the existing unique constraint on email
-- Note: In PostgreSQL, UNIQUE constraints create implicit indexes
-- We need to find and drop the constraint name
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    -- Find the unique constraint on email column
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'users'::regclass
    AND contype = 'u'
    AND array_length(conkey, 1) = 1
    AND conkey[1] = (SELECT attnum FROM pg_attribute
                     WHERE attrelid = 'users'::regclass AND attname = 'email');

    -- Drop it if found
    IF constraint_name IS NOT NULL THEN
        EXECUTE 'ALTER TABLE users DROP CONSTRAINT ' || constraint_name;
    END IF;
END $$;

-- Step 6: Create new composite unique constraint (app_id, email)
-- Now same email can exist in different apps
ALTER TABLE users
ADD CONSTRAINT users_app_email_unique UNIQUE (app_id, email);

-- ============================================================================
-- PART 3: Add social login support
-- ============================================================================

-- Step 7: Add provider fields for OAuth/Social login
ALTER TABLE users
ADD COLUMN provider VARCHAR(50),
ADD COLUMN provider_id VARCHAR(255);

-- Step 8: Add composite unique constraint for social login
-- Prevents same Google/GitHub account from registering twice in same app
CREATE UNIQUE INDEX users_app_provider_unique
ON users(app_id, provider, provider_id)
WHERE provider IS NOT NULL AND provider_id IS NOT NULL;

-- Step 9: Make password_hash nullable (required for social login users)
ALTER TABLE users
ALTER COLUMN password_hash DROP NOT NULL;

-- Step 10: Add check constraint to ensure either password or provider exists
ALTER TABLE users
ADD CONSTRAINT users_auth_method_check
CHECK (
    (password_hash IS NOT NULL AND provider IS NULL) OR
    (password_hash IS NULL AND provider IS NOT NULL) OR
    (password_hash IS NOT NULL AND provider IS NOT NULL)
);

-- Step 11: Create indexes for social login lookups
CREATE INDEX idx_users_provider ON users(provider)
WHERE provider IS NOT NULL;

CREATE INDEX idx_users_provider_id ON users(app_id, provider, provider_id)
WHERE provider IS NOT NULL AND provider_id IS NOT NULL;

-- ============================================================================
-- PART 4: Add app_id to sessions table
-- ============================================================================

-- Step 12: Add app_id to sessions as nullable first
ALTER TABLE sessions
ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE CASCADE;

-- Step 13: Migrate existing sessions to base app
UPDATE sessions
SET app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
WHERE app_id IS NULL;

-- Step 14: Make app_id NOT NULL
ALTER TABLE sessions
ALTER COLUMN app_id SET NOT NULL;

-- Step 15: Create index for app_id filtering
CREATE INDEX idx_sessions_app_id ON sessions(app_id);

-- Step 16: Create composite index for common query pattern
CREATE INDEX idx_sessions_user_app ON sessions(user_id, app_id);

-- ============================================================================
-- PART 5: Update audit_logs for multi-tenant context
-- ============================================================================

-- Step 17: Add app_id to audit_logs for context
ALTER TABLE audit_logs
ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE SET NULL;

-- Step 18: Create index for filtering audit logs by app
CREATE INDEX idx_audit_logs_app_id ON audit_logs(app_id);

-- ============================================================================
-- PART 6: Documentation and comments
-- ============================================================================

COMMENT ON COLUMN users.app_id IS 'Application (realm) this user belongs to. Users are isolated per app.';
COMMENT ON COLUMN users.provider IS 'OAuth provider name (google, github, etc.) or NULL for email/password';
COMMENT ON COLUMN users.provider_id IS 'Unique user ID from OAuth provider';
COMMENT ON CONSTRAINT users_app_email_unique ON users IS 'Email is unique within an app, but can exist in multiple apps';
COMMENT ON CONSTRAINT users_auth_method_check ON users IS 'User must have either password_hash, provider, or both';

COMMENT ON COLUMN sessions.app_id IS 'Application context for this session. User can have separate sessions per app.';

COMMENT ON COLUMN audit_logs.app_id IS 'Application context where the event occurred (nullable for system events)';

-- ============================================================================
-- PART 7: Data validation
-- ============================================================================

-- Verify migration succeeded
DO $$
DECLARE
    orphan_users INTEGER;
    orphan_sessions INTEGER;
    users_without_auth INTEGER;
BEGIN
    -- Check for orphan users (shouldn't exist)
    SELECT COUNT(*) INTO orphan_users
    FROM users
    WHERE app_id IS NULL;

    IF orphan_users > 0 THEN
        RAISE EXCEPTION 'Migration failed: % users without app_id', orphan_users;
    END IF;

    -- Check for orphan sessions
    SELECT COUNT(*) INTO orphan_sessions
    FROM sessions
    WHERE app_id IS NULL;

    IF orphan_sessions > 0 THEN
        RAISE EXCEPTION 'Migration failed: % sessions without app_id', orphan_sessions;
    END IF;

    -- Check for users without authentication method
    SELECT COUNT(*) INTO users_without_auth
    FROM users
    WHERE password_hash IS NULL AND provider IS NULL;

    IF users_without_auth > 0 THEN
        RAISE EXCEPTION 'Migration failed: % users without authentication method', users_without_auth;
    END IF;

    RAISE NOTICE 'Migration 005 validation: OK';
    RAISE NOTICE '  - All users have app_id';
    RAISE NOTICE '  - All sessions have app_id';
    RAISE NOTICE '  - All users have authentication method';
END $$;

-- ============================================================================
-- Migration Complete
-- ============================================================================

-- Summary of changes:
-- ✅ users.app_id added (NOT NULL, FK to apps)
-- ✅ Unique constraint changed from (email) to (app_id, email)
-- ✅ Social login fields added (provider, provider_id)
-- ✅ Unique constraint added (app_id, provider, provider_id)
-- ✅ password_hash now nullable for social login users
-- ✅ sessions.app_id added (NOT NULL, FK to apps)
-- ✅ audit_logs.app_id added (nullable)
-- ✅ All existing data migrated to base app
-- ✅ Indexes created for performance
-- ✅ Data validated for integrity
