-- Migration 002: Seed Default Roles and Permissions
-- Description: Crea app base, roles por defecto y permisos iniciales

-- Crear app base del sistema (para usuarios normales)
INSERT INTO apps (id, name, client_id, client_secret_hash, redirect_uris, allowed_scopes, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'Auth Service - Base App',
    'auth-service-base',
    -- Hash de un secret básico (cambiar en producción)
    '$argon2id$v=19$m=65536,t=3,p=2$base64salt$base64hash',
    ARRAY['http://localhost:3000', 'http://localhost:8080'],
    ARRAY['openid', 'profile', 'email'],
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Crear permisos base del sistema
INSERT INTO permissions (id, name, resource, action, description, created_at) VALUES
    -- User permissions
    ('10000000-0000-0000-0000-000000000001', 'Read Own Profile', 'users', 'read:own', 'Can read own user profile', NOW()),
    ('10000000-0000-0000-0000-000000000002', 'Update Own Profile', 'users', 'update:own', 'Can update own user profile', NOW()),

    -- Admin permissions - Users
    ('10000000-0000-0000-0000-000000000010', 'List All Users', 'users', 'read:all', 'Can list all users', NOW()),
    ('10000000-0000-0000-0000-000000000011', 'Create User', 'users', 'create', 'Can create new users', NOW()),
    ('10000000-0000-0000-0000-000000000012', 'Update Any User', 'users', 'update:any', 'Can update any user', NOW()),
    ('10000000-0000-0000-0000-000000000013', 'Delete User', 'users', 'delete', 'Can delete users', NOW()),

    -- Admin permissions - Roles
    ('10000000-0000-0000-0000-000000000020', 'List Roles', 'roles', 'read', 'Can list all roles', NOW()),
    ('10000000-0000-0000-0000-000000000021', 'Create Role', 'roles', 'create', 'Can create new roles', NOW()),
    ('10000000-0000-0000-0000-000000000022', 'Update Role', 'roles', 'update', 'Can update roles', NOW()),
    ('10000000-0000-0000-0000-000000000023', 'Delete Role', 'roles', 'delete', 'Can delete roles', NOW()),
    ('10000000-0000-0000-0000-000000000024', 'Assign Roles', 'roles', 'assign', 'Can assign roles to users', NOW()),

    -- Admin permissions - Sessions
    ('10000000-0000-0000-0000-000000000030', 'View All Sessions', 'sessions', 'read:all', 'Can view all user sessions', NOW()),
    ('10000000-0000-0000-0000-000000000031', 'Revoke Any Session', 'sessions', 'revoke:any', 'Can revoke any user session', NOW()),

    -- Admin permissions - Audit
    ('10000000-0000-0000-0000-000000000040', 'View Audit Logs', 'audit', 'read', 'Can view audit logs', NOW())
ON CONFLICT (resource, action) DO NOTHING;

-- Crear roles por defecto para la app base
INSERT INTO roles (id, app_id, name, description, created_at, updated_at) VALUES
    (
        '20000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000000',
        'user',
        'Usuario estándar con permisos básicos',
        NOW(),
        NOW()
    ),
    (
        '20000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000000',
        'admin',
        'Administrador con acceso completo al sistema',
        NOW(),
        NOW()
    ),
    (
        '20000000-0000-0000-0000-000000000003',
        '00000000-0000-0000-0000-000000000000',
        'moderator',
        'Moderador con permisos limitados de administración',
        NOW(),
        NOW()
    )
ON CONFLICT (app_id, name) DO NOTHING;

-- Asignar permisos al rol 'user'
INSERT INTO role_permissions (role_id, permission_id, created_at) VALUES
    -- Usuarios normales pueden leer y actualizar su propio perfil
    ('20000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001', NOW()),
    ('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Asignar permisos al rol 'moderator'
INSERT INTO role_permissions (role_id, permission_id, created_at) VALUES
    -- Moderadores heredan permisos de usuarios
    ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001', NOW()),
    ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002', NOW()),
    -- Y pueden ver usuarios y sesiones
    ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000010', NOW()),
    ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000030', NOW()),
    ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000040', NOW())
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Asignar TODOS los permisos al rol 'admin'
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT
    '20000000-0000-0000-0000-000000000002',
    id,
    NOW()
FROM permissions
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Crear índices para mejorar performance
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- Agregar comentarios para documentación
COMMENT ON TABLE apps IS 'Aplicaciones registradas que usan el servicio de autenticación';
COMMENT ON TABLE roles IS 'Roles definidos por aplicación para control de acceso';
COMMENT ON TABLE permissions IS 'Permisos granulares del sistema';
COMMENT ON TABLE role_permissions IS 'Asignación de permisos a roles';
COMMENT ON TABLE user_roles IS 'Asignación de roles a usuarios por aplicación';

-- Función helper para asignar rol por defecto
CREATE OR REPLACE FUNCTION assign_default_role()
RETURNS TRIGGER AS $$
DECLARE
    base_app_id UUID := '00000000-0000-0000-0000-000000000000';
    user_role_id UUID := '20000000-0000-0000-0000-000000000001';
BEGIN
    -- Auto-asignar rol 'user' a nuevos usuarios
    INSERT INTO user_roles (user_id, role_id, assigned_at)
    VALUES (NEW.id, user_role_id, NOW())
    ON CONFLICT (user_id, role_id) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger para auto-asignar rol en registro
DROP TRIGGER IF EXISTS auto_assign_user_role ON users;
CREATE TRIGGER auto_assign_user_role
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION assign_default_role();

-- Vista helper para obtener permisos de un usuario fácilmente
CREATE OR REPLACE VIEW user_permissions AS
SELECT
    ur.user_id,
    r.app_id,
    r.name as role_name,
    p.id as permission_id,
    p.name as permission_name,
    p.resource,
    p.action
FROM user_roles ur
JOIN roles r ON ur.role_id = r.id
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id;

COMMENT ON VIEW user_permissions IS 'Vista que combina usuarios, roles y permisos para consultas rápidas';
