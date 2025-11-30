# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [1.2.0] - 2024-12-01

### ✨ Agregado

- **User Management Endpoints**: Endpoints de administración de usuarios
  - Endpoint `GET /api/v1/admin/users` - Listar usuarios con paginación y búsqueda
  - Endpoint `GET /api/v1/admin/users/:id` - Obtener usuario específico
  - Respuestas incluyen array de roles asignados a cada usuario
  - Paginación: limit (default 20, max 100), page (default 1)
  - Búsqueda: por email, first_name, last_name (ILIKE)

### 📝 Documentación

- **Consolidación**: Reducida documentación de 10 archivos .md a 3 principales
  - `README.md` - Overview y quick start
  - `CLAUDE.md` - Documentación central completa (todo en uno)
  - `CHANGELOG.md` - Historial de versiones
  - Carpeta `docs/` con documentación técnica (architecture, diagrams, roadmap, openapi)

- **Scripts**: Simplificados de 3 scripts a 1
  - Solo `scripts/full-setup.sh` (incluye generación de claves y creación de admin)
  - Eliminados `generate-keys.sh` y `create-first-admin.sh` (redundantes)
  - Admins adicionales se crean vía API endpoints

- Actualizado `docs/openapi.yaml` con:
  - Endpoints de listado de usuarios
  - Schema `UserWithRoles` con array de roles
  - Parámetros de paginación y búsqueda
  - Versión actualizada a 1.2.0

### 🛠️ Técnico

- Agregado método `List()` en UserRepository con paginación y búsqueda
- Agregado método `GetUserRolesAllApps()` para obtener roles de usuario
- Implementada query SQL con ILIKE para búsqueda case-insensitive
- Handlers retornan struct `UserWithRoles` con roles embebidos

---

## [1.1.0] - 2024-11-30

### 🔧 Corregido (CRÍTICO)

- **Token Blacklist Bug**: Corregido bug crítico donde el reset de contraseña invalidaba TODOS los tokens, incluyendo los nuevos
  - **Problema**: Se guardaba timestamp futuro (NOW + 24h) en lugar de timestamp actual
  - **Impacto**: Usuarios no podían hacer login después de resetear contraseña
  - **Solución**: Cambiar a timestamp actual, solo invalidar tokens emitidos ANTES del reset
  - **Archivos**: `pkg/blacklist/blacklist.go`, `internal/service/auth_service.go`, `internal/service/user_service.go`

### ✨ Agregado

- **Password Reset Flow**: Flujo completo de reset de contraseña por email
  - Endpoint `POST /api/v1/auth/forgot-password` - Solicitar reset
  - Endpoint `POST /api/v1/auth/reset-password` - Resetear con token
  - Token expira en 1 hora
  - Invalidación automática de sesiones y tokens antiguos
  - Email de confirmación

- **Email Verification**: Verificación de email al registrarse
  - Endpoint `GET /api/v1/auth/verify-email/{token}` - Verificar email
  - Endpoint `POST /api/v1/auth/resend-verification` - Reenviar email
  - Token expira en 24 horas
  - Email de bienvenida al verificar

- **Change Password**: Cambio de contraseña para usuarios autenticados
  - Endpoint `PUT /api/v1/users/me/password` - Cambiar contraseña
  - Requiere contraseña actual para validación
  - Invalidación automática de sesiones y tokens

- **Email Service**: Integración con Resend
  - Emails transaccionales (verificación, reset, bienvenida, confirmación)
  - Templates HTML personalizados
  - Envío asíncrono para no bloquear requests

- **Testing**: Script automatizado de pruebas
  - `test-reset-flow.sh` - Prueba completa del flujo de reset
  - Valida invalidación de tokens antiguos
  - Valida funcionamiento de tokens nuevos

### 📝 Documentación

- Actualizado `CLAUDE.md` con:
  - Documentación completa del sistema de blacklist
  - Explicación de la corrección aplicada
  - Ejemplos de flujos de seguridad
  - Sección de testing automatizado

- Actualizado `docs/openapi.yaml` con:
  - Endpoints de forgot-password y reset-password
  - Endpoints de verificación de email
  - Endpoint de cambio de contraseña
  - Documentación del sistema de blacklist
  - Changelog en metadata

### 🔒 Seguridad

- **Mejorada**: Invalidación de tokens por timestamp
  - Tokens antiguos se invalidan correctamente
  - Tokens nuevos funcionan inmediatamente
  - No hay ventana de vulnerabilidad
  - TTL automático de 24h en Redis

- **Mejorada**: Reset de contraseña
  - Token de un solo uso
  - Expiración en 1 hora
  - Invalidación de todas las sesiones
  - Email de confirmación

### 🛠️ Técnico

- Agregada dependencia circular controlada: `UserService` → `AuthService`
- Método `SetAuthService()` para inyección de dependencia
- Refactorizado `BlacklistUser()` para usar TTL en lugar de timestamp futuro
- Mejorado manejo de errores en servicios de email

---

## [1.0.0] - 2024-11-15

### 🎉 Release Inicial

#### ✨ Características

- **Autenticación**
  - Registro de usuarios con validación
  - Login con email/password
  - JWT con RS256 (asimétrico)
  - Access token (15 min) y Refresh token (7 días)
  - Token rotation automático
  - Logout con invalidación de sesión

- **Autorización (RBAC)**
  - Sistema de roles por aplicación
  - 3 roles predefinidos: user, moderator, admin
  - 14 permisos granulares
  - Auto-asignación de rol "user" en registro
  - Middlewares de autorización
  - Gestión completa de roles (CRUD)

- **Seguridad**
  - Password hashing con Argon2id
  - Account locking (5 intentos → 15 min)
  - CORS configurable
  - Refresh tokens hasheados (SHA-256)
  - Sesiones en PostgreSQL

- **Infraestructura**
  - Docker Compose setup
  - PostgreSQL 16 + Redis 7
  - Health checks (/health, /ready)
  - Graceful shutdown
  - Connection pooling
  - Migraciones SQL versionadas

#### 📝 Documentación

- README.md completo
- ARCHITECTURE.md con diagramas
- RBAC_GUIDE.md detallado
- TESTING_RBAC.md paso a paso
- OpenAPI 3.0 specification
- Scripts de automatización

#### 🛠️ Stack Técnico

- Go 1.24
- Fiber v2 (web framework)
- PostgreSQL 16
- Redis 7
- JWT con RS256
- Argon2id para passwords
- Docker + Docker Compose

---

## Tipos de Cambios

- `✨ Agregado` - Nueva funcionalidad
- `🔧 Corregido` - Bug fix
- `🔒 Seguridad` - Mejora de seguridad
- `📝 Documentación` - Cambios en documentación
- `🛠️ Técnico` - Cambios técnicos internos
- `⚠️ Deprecado` - Funcionalidad que será removida
- `🗑️ Removido` - Funcionalidad removida
- `🚀 Performance` - Mejora de rendimiento

---

## Links

- [Repositorio](https://github.com/your-org/auth-service)
- [Documentación](./CLAUDE.md)
- [Issues](https://github.com/your-org/auth-service/issues)
- [Roadmap](./docs/roadmap.md)
