# Guía de Pruebas - Sistema RBAC

## 🚀 Quick Start

### 1. Aplicar Migraciones

```bash
# Levantar servicios
make docker-up

# Esperar que PostgreSQL esté listo
sleep 5

# Aplicar migración inicial (si no se aplicó automáticamente)
docker-compose exec -T postgres psql -U auth -d authdb < migrations/001_initial.sql

# Aplicar migración de roles y permisos
docker-compose exec -T postgres psql -U auth -d authdb < migrations/002_seed_default_roles.sql
```

### 2. Compilar y Ejecutar

```bash
# Compilar
make build

# Ejecutar
./bin/auth-service
```

O simplemente:
```bash
make run
```

---

## 📝 Escenario de Prueba Completo

### Paso 1: Registrar Usuarios

**Usuario Normal:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@test.com",
    "password": "TestPass123!",
    "first_name": "Regular",
    "last_name": "User"
  }'
```

**Usuario Admin (inicialmente será user):**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "AdminPass123!",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

**Guardar los IDs de usuario de las respuestas**

---

### Paso 2: Promover al Admin (Directamente en DB)

Como aún no tenemos un admin, necesitamos crear uno manualmente:

```bash
# Conectarse a PostgreSQL
docker-compose exec postgres psql -U auth -d authdb

# Obtener el user_id del admin@test.com
SELECT id FROM users WHERE email = 'admin@test.com';

# Asignar rol admin (reemplaza USER_ID con el UUID obtenido)
INSERT INTO user_roles (user_id, role_id, assigned_at)
VALUES (
  'USER_ID_HERE',
  '20000000-0000-0000-0000-000000000002',  -- ID del rol admin
  NOW()
);

# Salir
\q
```

---

### Paso 3: Login de Usuarios

**Login como Usuario Normal:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@test.com",
    "password": "TestPass123!",
    "app_id": "00000000-0000-0000-0000-000000000000"
  }' | jq .
```

**Guardar el access_token en una variable:**
```bash
USER_TOKEN="eyJhbGc..."
```

**Login como Admin:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "AdminPass123!",
    "app_id": "00000000-0000-0000-0000-000000000000"
  }' | jq .
```

**Guardar el access_token:**
```bash
ADMIN_TOKEN="eyJhbGc..."
```

---

### Paso 4: Verificar Roles y Permisos

**Ver roles del usuario normal:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/roles \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
```

**Resultado esperado:**
```json
{
  "roles": [
    {
      "id": "20000000-0000-0000-0000-000000000001",
      "app_id": "00000000-0000-0000-0000-000000000000",
      "name": "user",
      "description": "Usuario estándar con permisos básicos"
    }
  ],
  "count": 1
}
```

**Ver roles del admin:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Resultado esperado:**
```json
{
  "roles": [
    {
      "name": "user",
      ...
    },
    {
      "name": "admin",
      ...
    }
  ],
  "count": 2
}
```

**Ver permisos del usuario normal:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/permissions \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
```

**Ver permisos del admin:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/permissions \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

---

### Paso 5: Probar Endpoints de Admin

**Listar todos los roles (como admin):**
```bash
curl -X GET "http://localhost:8080/api/v1/admin/roles?app_id=00000000-0000-0000-0000-000000000000" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Intentar listar roles como usuario normal (debe fallar):**
```bash
curl -X GET "http://localhost:8080/api/v1/admin/roles?app_id=00000000-0000-0000-0000-000000000000" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
```

**Resultado esperado:**
```json
{
  "error": "Forbidden: insufficient permissions",
  "required_roles": ["admin"]
}
```

---

### Paso 6: Crear un Rol Personalizado

**Crear rol "editor" (como admin):**
```bash
curl -X POST http://localhost:8080/api/v1/admin/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "00000000-0000-0000-0000-000000000000",
    "name": "editor",
    "description": "Editor con permisos de moderación"
  }' | jq .
```

**Guardar el ID del rol creado:**
```bash
EDITOR_ROLE_ID="uuid-del-rol-editor"
```

---

### Paso 7: Asignar Roles a Usuarios

**Obtener ID del usuario normal:**
```bash
# Desde el login response o:
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $USER_TOKEN" | jq .id
```

**Asignar rol "editor" al usuario normal:**
```bash
curl -X POST "http://localhost:8080/api/v1/admin/users/REGULAR_USER_ID/roles/$EDITOR_ROLE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Verificar que se asignó:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/roles \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
```

**Ahora debería ver 2 roles: "user" y "editor"**

---

### Paso 8: Remover Rol

**Remover rol "editor":**
```bash
curl -X DELETE "http://localhost:8080/api/v1/admin/users/REGULAR_USER_ID/roles/$EDITOR_ROLE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Verificar que se removió:**
```bash
curl -X GET http://localhost:8080/api/v1/users/me/roles \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
```

---

### Paso 9: Intentar Eliminar un Rol con Usuarios Asignados

**Asignar rol moderator a alguien:**
```bash
MODERATOR_ROLE_ID="20000000-0000-0000-0000-000000000003"

curl -X POST "http://localhost:8080/api/v1/admin/users/REGULAR_USER_ID/roles/$MODERATOR_ROLE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Intentar eliminar el rol moderator:**
```bash
curl -X DELETE "http://localhost:8080/api/v1/admin/roles/$MODERATOR_ROLE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Resultado esperado:**
```json
{
  "error": "Cannot delete role with assigned users"
}
```

---

### Paso 10: Ver Permisos de un Rol

**Ver permisos del rol "admin":**
```bash
ADMIN_ROLE_ID="20000000-0000-0000-0000-000000000002"

curl -X GET "http://localhost:8080/api/v1/admin/roles/$ADMIN_ROLE_ID/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Debería listar TODOS los permisos del sistema**

**Ver permisos del rol "user":**
```bash
USER_ROLE_ID="20000000-0000-0000-0000-000000000001"

curl -X GET "http://localhost:8080/api/v1/admin/roles/$USER_ROLE_ID/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Debería mostrar solo 2 permisos: read:own y update:own**

---

## ✅ Checklist de Funcionalidades

### Rol User (Auto-asignado)
- [x] Se asigna automáticamente en registro
- [x] Puede ver su propio perfil (GET /users/me)
- [x] Puede ver sus roles (GET /users/me/roles)
- [x] Puede ver sus permisos (GET /users/me/permissions)
- [x] NO puede acceder a /admin/*
- [x] NO puede acceder a /moderator/*

### Rol Moderator
- [x] Debe ser asignado por admin
- [x] Puede ver roles de otros usuarios (GET /moderator/users/:id/roles)
- [x] Puede ver todos los usuarios (permiso users:read:all)
- [x] Puede ver audit logs (permiso audit:read)
- [x] NO puede crear/editar/eliminar roles
- [x] NO puede asignar roles a usuarios

### Rol Admin
- [x] Debe ser asignado manualmente (primer admin via DB)
- [x] Puede crear roles (POST /admin/roles)
- [x] Puede listar roles (GET /admin/roles)
- [x] Puede actualizar roles (PUT /admin/roles/:id)
- [x] Puede eliminar roles (DELETE /admin/roles/:id)
- [x] Puede asignar roles a usuarios (POST /admin/users/:id/roles/:roleId)
- [x] Puede remover roles de usuarios (DELETE /admin/users/:id/roles/:roleId)
- [x] Puede ver permisos de roles (GET /admin/roles/:id/permissions)
- [x] Tiene TODOS los permisos del sistema

### Middlewares
- [x] RequireRole funciona correctamente
- [x] RequirePermission funciona correctamente
- [x] RequireAdmin = RequireRole("admin")
- [x] RequireModerator = RequireRole("admin", "moderator")
- [x] Mensajes de error claros

---

## 🐛 Debugging

### Ver todos los roles en DB

```sql
SELECT * FROM roles ORDER BY name;
```

### Ver todos los permisos en DB

```sql
SELECT * FROM permissions ORDER BY resource, action;
```

### Ver asignaciones de roles

```sql
SELECT
    u.email,
    r.name as role,
    ur.assigned_at
FROM user_roles ur
JOIN users u ON ur.user_id = u.id
JOIN roles r ON ur.role_id = r.id
ORDER BY u.email, r.name;
```

### Ver permisos de un usuario específico

```sql
SELECT * FROM user_permissions
WHERE user_id = 'USER_UUID_HERE'
ORDER BY resource, action;
```

### Verificar trigger de auto-asignación

```sql
-- El trigger debería ejecutarse automáticamente
-- Pero puedes verificarlo así:

SELECT routine_name
FROM information_schema.routines
WHERE routine_type = 'FUNCTION'
AND routine_name = 'assign_default_role';

SELECT * FROM information_schema.triggers
WHERE trigger_name = 'auto_assign_user_role';
```

---

## 📊 Resultados Esperados

### Al registrarse:
✅ Usuario creado
✅ Rol "user" asignado automáticamente (sin necesidad de código Go adicional)
✅ Token devuelto con roles en claims

### Como usuario normal:
✅ Puede ver su perfil
✅ Puede ver sus roles y permisos
❌ No puede acceder a endpoints /admin
❌ No puede acceder a endpoints /moderator

### Como admin:
✅ Puede gestionar todos los roles
✅ Puede asignar/remover roles de cualquier usuario
✅ Puede ver permisos de cualquier rol
✅ Puede acceder a endpoints /admin y /moderator

---

## 🎯 Próximos Pasos

1. ✅ Sistema RBAC funcional
2. ⏳ Agregar más permisos según necesidades
3. ⏳ Implementar audit logging para cambios de roles
4. ⏳ Crear UI de administración
5. ⏳ Exportar permisos en JWT claims para validación offline

---

**Todo listo!** El sistema RBAC está completamente implementado y probado.
