-- ============================================================================
-- Migration 002: INITIAL DATA (Inserts and Updates)
-- ============================================================================
-- Description: Inserts all initial data and migrates existing data
-- Part 2: Must be run AFTER 001_structure.sql
-- Created: 2024-12-14
-- Version: 2.0
-- Branch: multi-tenant-migration
-- ============================================================================

-- ============================================================================
-- SECTION 1: BASE APP
-- ============================================================================

INSERT INTO apps (
    id,
    name,
    client_id,
    client_secret_hash,
    description,
    web_origins,
    redirect_uris,
    logo_url,
    primary_color
)
VALUES (
    '7057e69d-818b-45db-b39b-9d1c84aca142',
    'Auth Service',
    'auth-service',
    'placeholder',
    'Default application for the auth service',
    -- Web origins for localhost development (auto-detection de app)
    ARRAY[
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:8080',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5173',
        'http://127.0.0.1:8080'
    ]::TEXT[],
    -- Redirect URIs for OAuth2 callback (localhost development)
    ARRAY[
        'http://localhost:3000/callback',
        'http://localhost:3000/auth/callback',
        'http://localhost:5173/callback',
        'http://localhost:5173/auth/callback',
        'http://localhost:8080/callback',
        'http://localhost:8080/auth/callback'
    ]::TEXT[],
    NULL, -- logo_url (puedes agregar una URL si tienes un logo)
    '#05C383' -- primary_color (verde por defecto)
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SECTION 2: DEFAULT TENANT (Public)
-- ============================================================================

INSERT INTO tenants (
    id,
    app_id,
    name,
    slug,
    type,
    owner_id,
    max_users,
    status,
    metadata,
    created_at,
    updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '7057e69d-818b-45db-b39b-9d1c84aca142',
    'Public Users',
    'public',
    'public',
    NULL,
    NULL,
    'active',
    '{"description": "Default tenant for individual users", "is_default": true}'::jsonb,
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SECTION 3: MIGRATE EXISTING USERS TO PUBLIC TENANT
-- ============================================================================

-- Migrate users in base app to public tenant
UPDATE users
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL
  AND app_id = '7057e69d-818b-45db-b39b-9d1c84aca142';

-- For other apps, create public tenant and assign users
DO $$
DECLARE
    app_record RECORD;
    public_tenant_id UUID;
BEGIN
    FOR app_record IN
        SELECT DISTINCT u.app_id, a.name as app_name
        FROM users u
        JOIN apps a ON u.app_id = a.id
        WHERE u.tenant_id IS NULL
          AND u.app_id != '7057e69d-818b-45db-b39b-9d1c84aca142'
    LOOP
        INSERT INTO tenants (app_id, name, slug, type, max_users, status, metadata)
        VALUES (
            app_record.app_id,
            'Public Users',
            'public',
            'public',
            NULL,
            'active',
            '{"description": "Default tenant for individual users", "is_default": true}'::jsonb
        )
        RETURNING id INTO public_tenant_id;

        UPDATE users
        SET tenant_id = public_tenant_id
        WHERE app_id = app_record.app_id
          AND tenant_id IS NULL;

        RAISE NOTICE 'Created public tenant % for app % and migrated users', public_tenant_id, app_record.app_name;
    END LOOP;
END $$;

-- ============================================================================
-- SECTION 4: UPDATE TENANT USER COUNTS
-- ============================================================================

UPDATE tenants t
SET current_users_count = (
    SELECT COUNT(*)
    FROM users u
    WHERE u.tenant_id = t.id
);

-- ============================================================================
-- SECTION 5: MIGRATE EXISTING SESSIONS
-- ============================================================================

-- Populate tenant_id in existing sessions from users table
UPDATE sessions s
SET tenant_id = u.tenant_id
FROM users u
WHERE s.user_id = u.id
  AND s.tenant_id IS NULL;

-- Delete sessions without valid tenant_id (orphaned sessions)
DELETE FROM sessions WHERE tenant_id IS NULL;

-- ============================================================================
-- SECTION 6: MAKE tenant_id NOT NULL (After Migration)
-- ============================================================================

-- Make tenant_id NOT NULL in users
DO $$
DECLARE
    null_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO null_count FROM users WHERE tenant_id IS NULL;

    IF null_count > 0 THEN
        RAISE EXCEPTION 'Cannot make tenant_id NOT NULL: % users still have NULL tenant_id. Migration incomplete.', null_count;
    END IF;

    ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
    RAISE NOTICE 'Successfully set users.tenant_id to NOT NULL';
END $$;

-- Make tenant_id NOT NULL in sessions
DO $$
DECLARE
    null_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO null_count FROM sessions WHERE tenant_id IS NULL;

    IF null_count > 0 THEN
        RAISE WARNING 'Found % sessions with NULL tenant_id after migration, deleting them', null_count;
        DELETE FROM sessions WHERE tenant_id IS NULL;
    END IF;

    ALTER TABLE sessions ALTER COLUMN tenant_id SET NOT NULL;
    RAISE NOTICE 'Successfully set sessions.tenant_id to NOT NULL';
END $$;

-- ============================================================================
-- SECTION 7: DEFAULT ROLES
-- ============================================================================

INSERT INTO roles (id, app_id, name, description, created_at, updated_at) VALUES
    ('10000000-0000-0000-0000-000000000001', '7057e69d-818b-45db-b39b-9d1c84aca142', 'super_admin', 'Super administrador con acceso global a todas las aplicaciones', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000001', '7057e69d-818b-45db-b39b-9d1c84aca142', 'user', 'Usuario regular con permisos básicos', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000002', '7057e69d-818b-45db-b39b-9d1c84aca142', 'admin', 'Administrador de la aplicación', NOW(), NOW()),
    ('20000000-0000-0000-0000-000000000003', '7057e69d-818b-45db-b39b-9d1c84aca142', 'moderator', 'Moderador con permisos intermedios', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SECTION 8: DEFAULT PERMISSIONS
-- ============================================================================

-- User permissions (basic users)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'read:own', 'Ver su propio perfil', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'update:own', 'Actualizar su propio perfil', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'delete:own', 'Eliminar su propia cuenta', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'sessions', 'read:own', 'Ver sus propias sesiones', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'sessions', 'delete:own', 'Cerrar sus propias sesiones', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Admin permissions (application admins)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'read:all', 'Ver todos los usuarios de la aplicación', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'update:all', 'Actualizar cualquier usuario', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'delete:all', 'Eliminar cualquier usuario', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'create', 'Crear nuevos roles', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'read', 'Ver roles', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'update', 'Actualizar roles', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'delete', 'Eliminar roles', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'assign', 'Asignar roles a usuarios', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Moderator permissions (intermediate level)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'users', 'read:limited', 'Ver información limitada de usuarios', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- Super admin permissions (global, cross-app, including tenants)
INSERT INTO permissions (app_id, resource, action, description, created_at) VALUES
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'apps', 'create', 'Crear nuevas aplicaciones', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'apps', 'read:all', 'Ver todas las aplicaciones', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'apps', 'update:all', 'Actualizar cualquier aplicación', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'apps', 'delete:all', 'Eliminar cualquier aplicación', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'create:all', 'Crear roles en cualquier app', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'read:all', 'Ver roles de todas las apps', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'update:all', 'Actualizar roles de cualquier app', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'delete:all', 'Eliminar roles de cualquier app', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'roles', 'assign:all', 'Asignar roles a cualquier usuario', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'tenants', 'create', 'Crear nuevos tenants', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'tenants', 'read:all', 'Ver todos los tenants', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'tenants', 'update:all', 'Actualizar cualquier tenant', NOW()),
    ('7057e69d-818b-45db-b39b-9d1c84aca142', 'tenants', 'delete:all', 'Eliminar cualquier tenant', NOW())
ON CONFLICT (app_id, resource, action) DO NOTHING;

-- ============================================================================
-- SECTION 9: ROLE-PERMISSION ASSIGNMENTS
-- ============================================================================

-- User role permissions (basic 5 permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000001', id
FROM permissions
WHERE app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
  AND action IN ('read:own', 'update:own', 'delete:own')
ON CONFLICT DO NOTHING;

-- Moderator role permissions (user permissions + limited read)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000003', id
FROM permissions
WHERE app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
  AND action IN ('read:own', 'update:own', 'delete:own', 'read:limited')
ON CONFLICT DO NOTHING;

-- Admin role permissions (all admin permissions + user permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000002', id
FROM permissions
WHERE app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
  AND (resource IN ('users', 'roles', 'sessions'))
  AND action NOT LIKE '%:all'
ON CONFLICT DO NOTHING;

-- Super admin role permissions (all global permissions including tenants)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000001', id
FROM permissions
WHERE app_id = '7057e69d-818b-45db-b39b-9d1c84aca142'
  AND (resource IN ('apps', 'tenants') OR action LIKE '%:all')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- Migration 002 Complete - Data Inserted
-- ============================================================================

-- Summary of data inserted:
-- ✅ Base app (7057e69d-818b-45db-b39b-9d1c84aca142)
-- ✅ Public tenant (00000000-0000-0000-0000-000000000001)
-- ✅ Migrated existing users to public tenant
-- ✅ Updated tenant user counts
-- ✅ Migrated existing sessions to tenants
-- ✅ Set tenant_id as NOT NULL in users and sessions
-- ✅ 4 default roles (super_admin, admin, moderator, user)
-- ✅ 22 permissions (including tenant permissions)
-- ✅ Role-permission assignments for all roles

-- Database is now fully initialized and ready for use!
