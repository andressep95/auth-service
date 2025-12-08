-- migrations/004_add_super_admin.sql
-- Add super_admin role with global permissions

-- Create super_admin role in default app
INSERT INTO roles (id, app_id, name, description, created_at)
VALUES (
    '10000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000000',
    'super_admin',
    'Super administrador con acceso global a todas las aplicaciones',
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Create global permissions for super_admin
INSERT INTO permissions (id, app_id, resource, action, description, created_at)
VALUES
    -- App management
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'apps', 'create', 'Crear nuevas aplicaciones', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'apps', 'read:all', 'Ver todas las aplicaciones', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'apps', 'update:all', 'Actualizar cualquier aplicación', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'apps', 'delete:all', 'Eliminar cualquier aplicación', NOW()),
    
    -- Global user management
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'users', 'read:all', 'Ver todos los usuarios de todas las apps', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'users', 'update:all', 'Actualizar cualquier usuario', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'users', 'delete:all', 'Eliminar cualquier usuario', NOW()),
    
    -- Global role management
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'roles', 'create:all', 'Crear roles en cualquier app', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'roles', 'read:all', 'Ver roles de todas las apps', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'roles', 'update:all', 'Actualizar roles de cualquier app', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'roles', 'delete:all', 'Eliminar roles de cualquier app', NOW()),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'roles', 'assign:all', 'Asignar roles a cualquier usuario', NOW())
ON CONFLICT DO NOTHING;

-- Assign all super_admin permissions to super_admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    '10000000-0000-0000-0000-000000000001',
    id
FROM permissions
WHERE app_id = '00000000-0000-0000-0000-000000000000'
  AND (
    resource = 'apps' OR
    (resource = 'users' AND action LIKE '%:all') OR
    (resource = 'roles' AND action LIKE '%:all')
  )
ON CONFLICT DO NOTHING;

-- Add is_super_admin flag to users table for quick checks
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_users_is_super_admin ON users(is_super_admin) WHERE is_super_admin = TRUE;

COMMENT ON COLUMN users.is_super_admin IS 'Flag to quickly identify super admins without joining roles';

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('004_add_super_admin');
