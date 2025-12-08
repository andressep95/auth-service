-- ============================================================================
-- Migration 001: Complete Initial Schema for Multi-Tenant Auth Service
-- ============================================================================
-- Description: Complete database schema with multi-tenant support
-- This migration creates ALL tables needed for the auth service to run
-- Created: 2024-12-07
-- Version: 2.0 (Consolidated from multiple migrations)
-- ============================================================================

-- ============================================================================
-- PART 1: Base App (Required first)
-- ============================================================================

-- Apps table (applications that use the auth service)
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    client_id VARCHAR(64) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris TEXT[],
    allowed_scopes TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create base app (00000000-0000-0000-0000-000000000000)
-- This is the default app for the auth service itself
INSERT INTO apps (id, name, client_id, client_secret_hash, description)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'Auth Service',
    'auth-service',
    'placeholder',
    'Default application for the auth service'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- PART 2: Users Table (Multi-tenant + Email Verification + Social Login)
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255), -- Nullable for social login users
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'locked')),

    -- Email verification
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_token_expires_at TIMESTAMPTZ,

    -- Password reset
    password_reset_token VARCHAR(255),
    password_reset_token_expires_at TIMESTAMPTZ,

    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),

    -- Account security
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMPTZ,

    -- Social login (OAuth providers)
    provider VARCHAR(50), -- 'google', 'github', 'facebook', etc.
    provider_id VARCHAR(255), -- Unique ID from provider

    -- Super admin flag (for quick checks without joins)
    is_super_admin BOOLEAN DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,

    -- Constraints
    UNIQUE(app_id, email), -- Email unique per app
    UNIQUE(app_id, provider, provider_id) -- Prevent duplicate social logins per app
);

-- Check constraint: user must have either password OR provider (or both)
ALTER TABLE users ADD CONSTRAINT users_auth_method_check CHECK (
    (password_hash IS NOT NULL AND provider IS NULL) OR
    (password_hash IS NULL AND provider IS NOT NULL) OR
    (password_hash IS NOT NULL AND provider IS NOT NULL)
);

-- Indexes for users
CREATE INDEX idx_users_app_id ON users(app_id);
CREATE INDEX idx_users_email ON users(app_id, email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
CREATE INDEX idx_users_provider ON users(provider) WHERE provider IS NOT NULL;
CREATE INDEX idx_users_provider_id ON users(app_id, provider, provider_id) WHERE provider IS NOT NULL;
CREATE INDEX idx_users_is_super_admin ON users(is_super_admin) WHERE is_super_admin = TRUE;

-- Comments
COMMENT ON COLUMN users.app_id IS 'Application (realm) this user belongs to. Users are isolated per app.';
COMMENT ON COLUMN users.provider IS 'OAuth provider name (google, github, etc.) or NULL for email/password';
COMMENT ON COLUMN users.provider_id IS 'Unique user ID from OAuth provider';
COMMENT ON COLUMN users.is_super_admin IS 'Flag to quickly identify super admins without joining roles';
COMMENT ON COLUMN users.email_verification_token IS 'Token sent via email for verification (nullable after verification)';
COMMENT ON COLUMN users.password_reset_token IS 'Token sent via email for password reset (nullable, single use)';
COMMENT ON CONSTRAINT users_auth_method_check ON users IS 'User must have either password_hash, provider, or both';

-- ============================================================================
-- PART 3: Roles Table (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(app_id, name) -- Role name unique per app
);

CREATE INDEX idx_roles_app_id ON roles(app_id);
CREATE INDEX idx_roles_name ON roles(app_id, name);

-- ============================================================================
-- PART 4: Permissions Table (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(app_id, resource, action) -- Permission unique per app
);

CREATE INDEX idx_permissions_app_id ON permissions(app_id);
CREATE INDEX idx_permissions_resource ON permissions(app_id, resource);

-- ============================================================================
-- PART 5: Role-Permission Relationship (Many-to-Many)
-- ============================================================================

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- ============================================================================
-- PART 6: User-Role Relationship (Many-to-Many)
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- ============================================================================
-- PART 7: Sessions Table (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL, -- SHA-256 hash of refresh token
    user_agent VARCHAR(500),
    ip_address VARCHAR(45),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_app_id ON sessions(app_id);
CREATE INDEX idx_sessions_user_app ON sessions(user_id, app_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);

COMMENT ON COLUMN sessions.app_id IS 'Application context for this session. User can have separate sessions per app.';
COMMENT ON COLUMN sessions.refresh_token_hash IS 'SHA-256 hash of the refresh token (never store plain token)';

-- ============================================================================
-- PART 8: Audit Logs (Multi-tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID REFERENCES apps(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_app_id ON audit_logs(app_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

COMMENT ON COLUMN audit_logs.app_id IS 'Application context where the event occurred (nullable for system events)';

-- ============================================================================
-- PART 9: Default Roles (Base App)
-- ============================================================================

-- Insert default roles for the base app
INSERT INTO roles (id, app_id, name, description, created_at, updated_at) VALUES
    ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'super_admin', 'Super administrador con acceso global a todas las aplicaciones', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'user', 'Usuario regular con permisos básicos', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'admin', 'Administrador de la aplicación', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'moderator', 'Moderador con permisos intermedios', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- PART 10: Default Permissions (Base App)
-- ============================================================================

-- User permissions (basic users)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('00000000-0000-0000-0000-000000000000', 'users', 'read:own', 'Ver su propio perfil', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'users', 'update:own', 'Actualizar su propio perfil', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'users', 'delete:own', 'Eliminar su propia cuenta', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'sessions', 'read:own', 'Ver sus propias sesiones', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'sessions', 'delete:own', 'Cerrar sus propias sesiones', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Admin permissions (application admins)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('00000000-0000-0000-0000-000000000000', 'users', 'read:all', 'Ver todos los usuarios de la aplicación', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'users', 'update:all', 'Actualizar cualquier usuario', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'users', 'delete:all', 'Eliminar cualquier usuario', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'create', 'Crear nuevos roles', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'read', 'Ver roles', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'update', 'Actualizar roles', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'delete', 'Eliminar roles', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'assign', 'Asignar roles a usuarios', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Moderator permissions (intermediate level)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('00000000-0000-0000-0000-000000000000', 'users', 'read:limited', 'Ver información limitada de usuarios', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Super admin permissions (global, cross-app)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    -- App management
    ('00000000-0000-0000-0000-000000000000', 'apps', 'create', 'Crear nuevas aplicaciones', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'apps', 'read:all', 'Ver todas las aplicaciones', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'apps', 'update:all', 'Actualizar cualquier aplicación', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'apps', 'delete:all', 'Eliminar cualquier aplicación', NOW()),

    -- Global role management
    ('00000000-0000-0000-0000-000000000000', 'roles', 'create:all', 'Crear roles en cualquier app', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'read:all', 'Ver roles de todas las apps', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'update:all', 'Actualizar roles de cualquier app', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'delete:all', 'Eliminar roles de cualquier app', NOW()),
    ('00000000-0000-0000-0000-000000000000', 'roles', 'assign:all', 'Asignar roles a cualquier usuario', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- ============================================================================
-- PART 11: Assign Permissions to Roles
-- ============================================================================

-- User role permissions (basic 5 permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '20000000-0000-0000-0000-000000000001',
    id
FROM permissions
WHERE app_id = '00000000-0000-0000-0000-000000000000'
  AND action IN ('read:own', 'update:own', 'delete:own')
ON CONFLICT DO NOTHING;

-- Moderator role permissions (user permissions + limited read)
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '20000000-0000-0000-0000-000000000003',
    id
FROM permissions
WHERE app_id = '00000000-0000-0000-0000-000000000000'
  AND (
    action IN ('read:own', 'update:own', 'delete:own', 'read:limited')
  )
ON CONFLICT DO NOTHING;

-- Admin role permissions (all admin permissions + user permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '20000000-0000-0000-0000-000000000002',
    id
FROM permissions
WHERE app_id = '00000000-0000-0000-0000-000000000000'
  AND (
    resource = 'users' OR
    resource = 'roles' OR
    resource = 'sessions'
  )
  AND action NOT LIKE '%:all'
ON CONFLICT DO NOTHING;

-- Super admin role permissions (all global permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '10000000-0000-0000-0000-000000000001',
    id
FROM permissions
WHERE app_id = '00000000-0000-0000-0000-000000000000'
  AND (
    resource = 'apps' OR
    action LIKE '%:all'
  )
ON CONFLICT DO NOTHING;

-- ============================================================================
-- PART 12: Triggers and Functions
-- ============================================================================

-- Function to auto-assign 'user' role to new users
CREATE OR REPLACE FUNCTION auto_assign_user_role()
RETURNS TRIGGER AS $$
DECLARE
    base_app_id UUID := '00000000-0000-0000-0000-000000000000';
    user_role_id UUID := '20000000-0000-0000-0000-000000000001';
    target_role_id UUID;
BEGIN
    -- Find the 'user' role for this app
    SELECT id INTO target_role_id
    FROM roles
    WHERE app_id = NEW.app_id AND name = 'user';

    -- If no user role exists for this app, use the base app's user role
    IF target_role_id IS NULL THEN
        target_role_id := user_role_id;
    END IF;

    -- Assign the role
    INSERT INTO user_roles (user_id, role_id, assigned_at)
    VALUES (NEW.id, target_role_id, NOW())
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-assign user role on registration
DROP TRIGGER IF EXISTS auto_assign_user_role ON users;
CREATE TRIGGER auto_assign_user_role
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION auto_assign_user_role();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_apps_updated_at BEFORE UPDATE ON apps
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- PART 13: Utility Views
-- ============================================================================

-- View for user roles with details
CREATE OR REPLACE VIEW user_roles_detailed AS
SELECT
    ur.user_id,
    ur.role_id,
    r.app_id,
    r.name as role_name,
    r.description as role_description,
    ur.assigned_at
FROM user_roles ur
JOIN roles r ON ur.role_id = r.id;

COMMENT ON VIEW user_roles_detailed IS 'User roles with full role details for easier querying';

-- ============================================================================
-- PART 14: Additional Indexes for Performance
-- ============================================================================

-- Composite indexes for common queries
CREATE INDEX idx_users_app_email_lookup ON users(app_id, email) WHERE status = 'active';
CREATE INDEX idx_sessions_cleanup ON sessions(expires_at); -- Removed WHERE clause (NOW() not IMMUTABLE)
CREATE INDEX idx_user_roles_lookup ON user_roles(user_id, role_id);

-- ============================================================================
-- PART 15: Table Comments
-- ============================================================================

COMMENT ON TABLE apps IS 'Applications registered with the auth service (multi-tenant realms)';
COMMENT ON TABLE users IS 'Users belonging to applications (isolated per app_id)';
COMMENT ON TABLE roles IS 'Roles scoped to applications (RBAC per app)';
COMMENT ON TABLE permissions IS 'Permissions scoped to applications';
COMMENT ON TABLE sessions IS 'Active user sessions with refresh tokens (isolated per app)';
COMMENT ON TABLE audit_logs IS 'Audit trail of all actions in the system';
COMMENT ON TABLE user_roles IS 'User-Role assignments (many-to-many)';
COMMENT ON TABLE role_permissions IS 'Role-Permission assignments (many-to-many)';

-- ============================================================================
-- Migration Complete
-- ============================================================================

-- Summary of what was created:
-- ✅ Apps table with base app (00000000-0000-0000-0000-000000000000)
-- ✅ Users table with multi-tenant support (app_id)
-- ✅ Users table with email verification fields
-- ✅ Users table with password reset fields
-- ✅ Users table with social login support (provider, provider_id)
-- ✅ Users table with super_admin flag
-- ✅ Roles table with multi-tenant support
-- ✅ Permissions table with multi-tenant support
-- ✅ Sessions table with multi-tenant support
-- ✅ Audit logs table with multi-tenant support
-- ✅ Default roles: super_admin, user, admin, moderator
-- ✅ Default permissions for all roles
-- ✅ Role-permission assignments
-- ✅ Auto-assign user role trigger
-- ✅ Updated_at triggers
-- ✅ All necessary indexes for performance
-- ✅ Utility views for easier querying

-- The database is now fully initialized and ready for use!
