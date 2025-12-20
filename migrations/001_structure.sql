-- ============================================================================
-- Migration 001: DATABASE STRUCTURE (Tables, Constraints, Indexes, Functions, Triggers, Views)
-- ============================================================================
-- Description: Creates all database structure without data
-- Part 1: Structure only (no INSERT/UPDATE statements)
-- Created: 2024-12-14
-- Version: 2.0
-- Branch: multi-tenant-migration
-- ============================================================================

-- ============================================================================
-- SECTION 1: CREATE TABLES
-- ============================================================================

-- TABLE: apps
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris TEXT[] DEFAULT ARRAY[]::TEXT[],
    web_origins TEXT[] DEFAULT ARRAY[]::TEXT[],
    logo_url TEXT,
    primary_color VARCHAR(7) DEFAULT '#05C383',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: tenants
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    type VARCHAR(20) NOT NULL DEFAULT 'workspace',
    owner_id UUID,
    max_users INTEGER,
    current_users_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL,
    tenant_id UUID,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_token_expires_at TIMESTAMPTZ,
    password_reset_token VARCHAR(255),
    password_reset_token_expires_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    provider VARCHAR(50),
    provider_id VARCHAR(255),
    is_super_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- TABLE: roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: permissions
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: role_permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID,
    permission_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- TABLE: user_roles
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID,
    role_id UUID,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- TABLE: sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    app_id UUID NOT NULL,
    tenant_id UUID,
    refresh_token_hash VARCHAR(255) NOT NULL,
    user_agent VARCHAR(500),
    ip_address VARCHAR(45),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: authorization_codes (OAuth2 Authorization Code Flow)
CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash VARCHAR(255) NOT NULL UNIQUE,
    app_id UUID NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope VARCHAR(500),
    state VARCHAR(500),
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    used BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID,
    tenant_id UUID,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABLE: tenant_invitations
CREATE TABLE IF NOT EXISTS tenant_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    created_by UUID NOT NULL,
    role_id UUID,
    max_uses INTEGER,
    current_uses INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- SECTION 2: UNIQUE CONSTRAINTS
-- ============================================================================

ALTER TABLE apps ADD CONSTRAINT uq_apps_name UNIQUE (name);
ALTER TABLE apps ADD CONSTRAINT uq_apps_client_id UNIQUE (client_id);

ALTER TABLE tenants ADD CONSTRAINT uq_tenants_app_slug UNIQUE (app_id, slug);

ALTER TABLE users ADD CONSTRAINT uq_users_app_tenant_email UNIQUE (app_id, tenant_id, email);
ALTER TABLE users ADD CONSTRAINT uq_users_app_tenant_provider UNIQUE (app_id, tenant_id, provider, provider_id);

ALTER TABLE roles ADD CONSTRAINT uq_roles_app_name UNIQUE (app_id, name);

ALTER TABLE permissions ADD CONSTRAINT uq_permissions_app_resource_action UNIQUE (app_id, resource, action);

ALTER TABLE tenant_invitations ADD CONSTRAINT uq_invitations_token_hash UNIQUE (token_hash);

-- ============================================================================
-- SECTION 3: CHECK CONSTRAINTS
-- ============================================================================

ALTER TABLE users ADD CONSTRAINT chk_users_status
    CHECK (status IN ('active', 'inactive', 'locked'));

ALTER TABLE users ADD CONSTRAINT chk_users_auth_method CHECK (
    (password_hash IS NOT NULL AND provider IS NULL) OR
    (password_hash IS NULL AND provider IS NOT NULL) OR
    (password_hash IS NOT NULL AND provider IS NOT NULL)
);

ALTER TABLE tenants ADD CONSTRAINT chk_tenants_type
    CHECK (type IN ('public', 'workspace', 'enterprise'));

ALTER TABLE tenants ADD CONSTRAINT chk_tenants_status
    CHECK (status IN ('active', 'suspended', 'trial'));

ALTER TABLE tenants ADD CONSTRAINT chk_tenants_users_count_positive
    CHECK (current_users_count >= 0);

ALTER TABLE tenants ADD CONSTRAINT chk_tenants_max_users_respected
    CHECK (max_users IS NULL OR current_users_count <= max_users);

ALTER TABLE tenants ADD CONSTRAINT chk_tenants_slug_format
    CHECK (slug ~ '^[a-z0-9-]+$' AND LENGTH(slug) BETWEEN 3 AND 100);

ALTER TABLE tenant_invitations ADD CONSTRAINT chk_invitations_status
    CHECK (status IN ('active', 'expired', 'revoked'));

ALTER TABLE tenant_invitations ADD CONSTRAINT chk_invitations_uses_positive
    CHECK (current_uses >= 0);

ALTER TABLE tenant_invitations ADD CONSTRAINT chk_invitations_max_uses_respected
    CHECK (max_uses IS NULL OR current_uses <= max_uses);

-- ============================================================================
-- SECTION 4: FOREIGN KEY CONSTRAINTS
-- ============================================================================

ALTER TABLE tenants ADD CONSTRAINT fk_tenants_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE tenants ADD CONSTRAINT fk_tenants_owner_id
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE users ADD CONSTRAINT fk_users_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE users ADD CONSTRAINT fk_users_tenant_id
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE roles ADD CONSTRAINT fk_roles_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE permissions ADD CONSTRAINT fk_permissions_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_role_id
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_permission_id
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE;

ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role_id
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE sessions ADD CONSTRAINT fk_sessions_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE sessions ADD CONSTRAINT fk_sessions_tenant_id
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE authorization_codes ADD CONSTRAINT fk_authorization_codes_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE authorization_codes ADD CONSTRAINT fk_authorization_codes_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_app_id
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE SET NULL;

ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_tenant_id
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL;

ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE tenant_invitations ADD CONSTRAINT fk_invitations_tenant_id
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE tenant_invitations ADD CONSTRAINT fk_invitations_created_by
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE tenant_invitations ADD CONSTRAINT fk_invitations_role_id
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 5: INDEXES
-- ============================================================================

-- Apps indexes
CREATE INDEX IF NOT EXISTS idx_apps_client_id ON apps(client_id);

-- Tenants indexes
CREATE INDEX IF NOT EXISTS idx_tenants_app_id ON tenants(app_id);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(app_id, slug);
CREATE INDEX IF NOT EXISTS idx_tenants_owner ON tenants(owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tenants_type ON tenants(type);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status) WHERE status = 'active';

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_app_id ON users(app_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_app_tenant_email ON users(app_id, tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_users_app_tenant_status ON users(app_id, tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token)
    WHERE email_verification_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token)
    WHERE password_reset_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider) WHERE provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(app_id, tenant_id, provider, provider_id)
    WHERE provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_is_super_admin ON users(is_super_admin)
    WHERE is_super_admin = TRUE;

-- Roles indexes
CREATE INDEX IF NOT EXISTS idx_roles_app_id ON roles(app_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(app_id, name);

-- Permissions indexes
CREATE INDEX IF NOT EXISTS idx_permissions_app_id ON permissions(app_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(app_id, resource);

-- Role permissions indexes
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- User roles indexes
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_lookup ON user_roles(user_id, role_id);

-- Sessions indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_app_id ON sessions(app_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_tenant ON sessions(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);

-- Authorization codes indexes
CREATE INDEX IF NOT EXISTS idx_authorization_codes_code_hash ON authorization_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_app_id ON authorization_codes(app_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_used ON authorization_codes(used) WHERE used = FALSE;

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_app_id ON audit_logs(app_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Tenant invitations indexes
CREATE INDEX IF NOT EXISTS idx_invitations_tenant_id ON tenant_invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON tenant_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON tenant_invitations(created_by);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON tenant_invitations(status)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON tenant_invitations(expires_at)
    WHERE status = 'active';

-- ============================================================================
-- SECTION 6: FUNCTIONS
-- ============================================================================

-- Function: update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: auto-assign 'user' role to new users
CREATE OR REPLACE FUNCTION auto_assign_user_role()
RETURNS TRIGGER AS $$
DECLARE
    base_app_id UUID := '7057e69d-818b-45db-b39b-9d1c84aca142';
    user_role_id UUID := '20000000-0000-0000-0000-000000000001';
    target_role_id UUID;
BEGIN
    SELECT id INTO target_role_id
    FROM roles
    WHERE app_id = NEW.app_id AND name = 'user';

    IF target_role_id IS NULL THEN
        target_role_id := user_role_id;
    END IF;

    INSERT INTO user_roles (user_id, role_id, assigned_at)
    VALUES (NEW.id, target_role_id, NOW())
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: increment tenant user count
CREATE OR REPLACE FUNCTION increment_tenant_user_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE tenants
    SET current_users_count = current_users_count + 1
    WHERE id = NEW.tenant_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: decrement tenant user count
CREATE OR REPLACE FUNCTION decrement_tenant_user_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE tenants
    SET current_users_count = current_users_count - 1
    WHERE id = OLD.tenant_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Function: populate session tenant_id from user
CREATE OR REPLACE FUNCTION populate_session_tenant_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.tenant_id IS NULL THEN
        SELECT tenant_id INTO NEW.tenant_id
        FROM users
        WHERE id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: check if tenant has available quota
CREATE OR REPLACE FUNCTION check_tenant_quota(p_tenant_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_max_users INTEGER;
    v_current_count INTEGER;
BEGIN
    SELECT max_users, current_users_count
    INTO v_max_users, v_current_count
    FROM tenants
    WHERE id = p_tenant_id;

    IF v_max_users IS NULL THEN
        RETURN TRUE;
    END IF;

    RETURN v_current_count < v_max_users;
END;
$$ LANGUAGE plpgsql;

-- Function: get public tenant ID for an app
CREATE OR REPLACE FUNCTION get_public_tenant_id(p_app_id UUID)
RETURNS UUID AS $$
DECLARE
    v_tenant_id UUID;
BEGIN
    SELECT id INTO v_tenant_id
    FROM tenants
    WHERE app_id = p_app_id
      AND type = 'public'
      AND slug = 'public'
    LIMIT 1;

    IF v_tenant_id IS NULL THEN
        INSERT INTO tenants (app_id, name, slug, type, max_users, status, metadata)
        VALUES (
            p_app_id,
            'Public Users',
            'public',
            'public',
            NULL,
            'active',
            '{"description": "Default tenant for individual users", "is_default": true}'::jsonb
        )
        RETURNING id INTO v_tenant_id;
    END IF;

    RETURN v_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Function: enforce quota before creating user
CREATE OR REPLACE FUNCTION enforce_tenant_quota()
RETURNS TRIGGER AS $$
DECLARE
    quota_available BOOLEAN;
    tenant_name VARCHAR;
    max_limit INTEGER;
BEGIN
    quota_available := check_tenant_quota(NEW.tenant_id);

    IF NOT quota_available THEN
        SELECT name, max_users INTO tenant_name, max_limit
        FROM tenants
        WHERE id = NEW.tenant_id;

        RAISE EXCEPTION 'Tenant "%" has reached its maximum user limit of %',
            tenant_name, max_limit
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: transfer user to different tenant
CREATE OR REPLACE FUNCTION transfer_user_to_tenant(
    p_user_id UUID,
    p_new_tenant_id UUID
)
RETURNS VOID AS $$
DECLARE
    v_old_tenant_id UUID;
    v_app_id UUID;
    v_new_app_id UUID;
    v_email VARCHAR;
    v_duplicate_count INTEGER;
BEGIN
    SELECT tenant_id, app_id, email
    INTO v_old_tenant_id, v_app_id, v_email
    FROM users
    WHERE id = p_user_id;

    SELECT app_id INTO v_new_app_id
    FROM tenants
    WHERE id = p_new_tenant_id;

    IF v_app_id != v_new_app_id THEN
        RAISE EXCEPTION 'Cannot transfer user to tenant in different app';
    END IF;

    SELECT COUNT(*) INTO v_duplicate_count
    FROM users
    WHERE app_id = v_app_id
      AND tenant_id = p_new_tenant_id
      AND email = v_email;

    IF v_duplicate_count > 0 THEN
        RAISE EXCEPTION 'Email % already exists in target tenant', v_email;
    END IF;

    IF NOT check_tenant_quota(p_new_tenant_id) THEN
        RAISE EXCEPTION 'Target tenant has reached its user limit';
    END IF;

    UPDATE users SET tenant_id = p_new_tenant_id WHERE id = p_user_id;
    UPDATE sessions SET tenant_id = p_new_tenant_id WHERE user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 7: TRIGGERS
-- ============================================================================

-- Triggers for updated_at
CREATE TRIGGER update_apps_updated_at BEFORE UPDATE ON apps
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_invitations_updated_at BEFORE UPDATE ON tenant_invitations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger: auto-assign user role on registration
DROP TRIGGER IF EXISTS auto_assign_user_role ON users;
CREATE TRIGGER auto_assign_user_role
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION auto_assign_user_role();

-- Triggers: tenant user count management
DROP TRIGGER IF EXISTS increment_tenant_users ON users;
CREATE TRIGGER increment_tenant_users
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION increment_tenant_user_count();

DROP TRIGGER IF EXISTS decrement_tenant_users ON users;
CREATE TRIGGER decrement_tenant_users
    AFTER DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION decrement_tenant_user_count();

-- Trigger: populate session tenant_id
DROP TRIGGER IF EXISTS populate_session_tenant ON sessions;
CREATE TRIGGER populate_session_tenant
    BEFORE INSERT ON sessions
    FOR EACH ROW
    EXECUTE FUNCTION populate_session_tenant_id();

-- Trigger: enforce quota before user creation
DROP TRIGGER IF EXISTS enforce_quota_before_insert ON users;
CREATE TRIGGER enforce_quota_before_insert
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION enforce_tenant_quota();

-- ============================================================================
-- SECTION 8: VIEWS
-- ============================================================================

-- View: user roles with details
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

-- View: tenant statistics
CREATE OR REPLACE VIEW tenant_stats AS
SELECT
    t.id as tenant_id,
    t.app_id,
    t.name as tenant_name,
    t.slug,
    t.type,
    t.status,
    t.max_users,
    t.current_users_count,
    CASE
        WHEN t.max_users IS NULL THEN NULL
        ELSE ROUND((t.current_users_count::DECIMAL / t.max_users) * 100, 2)
    END as usage_percentage,
    COUNT(DISTINCT s.id) as active_sessions,
    t.created_at,
    u.email as owner_email,
    u.first_name || ' ' || u.last_name as owner_name
FROM tenants t
LEFT JOIN users u ON t.owner_id = u.id
LEFT JOIN sessions s ON s.tenant_id = t.id AND s.expires_at > NOW()
GROUP BY t.id, u.email, u.first_name, u.last_name;

-- View: users with tenant info
CREATE OR REPLACE VIEW users_with_tenant AS
SELECT
    u.id,
    u.app_id,
    u.tenant_id,
    t.name as tenant_name,
    t.slug as tenant_slug,
    t.type as tenant_type,
    u.email,
    u.first_name,
    u.last_name,
    u.status,
    u.email_verified,
    u.is_super_admin,
    u.created_at,
    u.last_login_at
FROM users u
JOIN tenants t ON u.tenant_id = t.id;

-- ============================================================================
-- SECTION 9: COMMENTS
-- ============================================================================

-- Table comments
COMMENT ON TABLE apps IS 'Applications registered with the auth service';
COMMENT ON TABLE tenants IS 'Workspaces/Organizations within apps for user isolation';
COMMENT ON TABLE users IS 'Users belonging to tenants within applications';
COMMENT ON TABLE roles IS 'RBAC roles scoped to applications';
COMMENT ON TABLE permissions IS 'RBAC permissions scoped to applications';
COMMENT ON TABLE role_permissions IS 'Role-Permission assignments (many-to-many)';
COMMENT ON TABLE user_roles IS 'User-Role assignments (many-to-many)';
COMMENT ON TABLE sessions IS 'Active user sessions with refresh tokens';
COMMENT ON TABLE audit_logs IS 'Audit trail of all actions in the system';
COMMENT ON TABLE tenant_invitations IS 'Invitation tokens for joining tenants via QR/links';

-- Column comments
COMMENT ON COLUMN users.app_id IS 'Application this user belongs to';
COMMENT ON COLUMN users.tenant_id IS 'Tenant (workspace/organization) this user belongs to';
COMMENT ON COLUMN users.provider IS 'OAuth provider (google, github, etc.) or NULL for email/password';
COMMENT ON COLUMN users.provider_id IS 'Unique user ID from OAuth provider';
COMMENT ON COLUMN users.is_super_admin IS 'Flag for super admins with global access';

COMMENT ON COLUMN tenants.app_id IS 'Application this tenant belongs to';
COMMENT ON COLUMN tenants.slug IS 'URL-friendly identifier (e.g., "acme-corp")';
COMMENT ON COLUMN tenants.type IS 'Type: public, workspace, enterprise';
COMMENT ON COLUMN tenants.owner_id IS 'User who owns/manages this tenant';
COMMENT ON COLUMN tenants.max_users IS 'Maximum users allowed (NULL = unlimited)';
COMMENT ON COLUMN tenants.current_users_count IS 'Current number of users (auto-maintained)';

COMMENT ON COLUMN sessions.tenant_id IS 'Tenant context (denormalized for performance)';
COMMENT ON COLUMN sessions.refresh_token_hash IS 'SHA-256 hash of refresh token';

COMMENT ON COLUMN audit_logs.tenant_id IS 'Tenant context (nullable for system events)';

COMMENT ON COLUMN tenant_invitations.token_hash IS 'SHA-256 hash of invitation token';

-- View comments
COMMENT ON VIEW user_roles_detailed IS 'User roles with full role details';
COMMENT ON VIEW tenant_stats IS 'Tenant statistics with quota usage and active sessions';
COMMENT ON VIEW users_with_tenant IS 'Users with denormalized tenant information';

-- Function comments
COMMENT ON FUNCTION check_tenant_quota(UUID) IS 'Checks if tenant has available user quota';
COMMENT ON FUNCTION get_public_tenant_id(UUID) IS 'Gets or creates public tenant for an app';
COMMENT ON FUNCTION transfer_user_to_tenant(UUID, UUID) IS 'Transfers user to different tenant (same app only)';

-- ============================================================================
-- Migration 001 Complete - Structure Ready
-- ============================================================================

-- Summary:
-- ✅ 10 tables created
-- ✅ 8 unique constraints
-- ✅ 10 check constraints
-- ✅ 17 foreign key constraints
-- ✅ 46 indexes
-- ✅ 9 functions
-- ✅ 10 triggers
-- ✅ 3 views
-- ✅ Full documentation (comments)

-- Next: Run 002_data.sql to insert initial data
