# Changelog

Todos los cambios notables en este proyecto ser\u00e1n documentados en este archivo.

El formato est\u00e1 basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [1.1.0] - 2024-11-30

### \ud83d\udd27 Corregido (CRÍTICO)

- **Token Blacklist Bug**: Corregido bug cr\u00edtico donde el reset de contrase\u00f1a invalidaba TODOS los tokens, incluyendo los nuevos
  - **Problema**: Se guardaba timestamp futuro (NOW + 24h) en lugar de timestamp actual
  - **Impacto**: Usuarios no pod\u00edan hacer login despu\u00e9s de resetear contrase\u00f1a
  - **Soluci\u00f3n**: Cambiar a timestamp actual, solo invalidar tokens emitidos ANTES del reset
  - **Archivos**: `pkg/blacklist/blacklist.go`, `internal/service/auth_service.go`, `internal/service/user_service.go`

### \u2728 Agregado

- **Password Reset Flow**: Flujo completo de reset de contrase\u00f1a por email
  - Endpoint `POST /api/v1/auth/forgot-password` - Solicitar reset
  - Endpoint `POST /api/v1/auth/reset-password` - Resetear con token
  - Token expira en 1 hora
  - Invalidaci\u00f3n autom\u00e1tica de sesiones y tokens antiguos
  - Email de confirmaci\u00f3n

- **Email Verification**: Verificaci\u00f3n de email al registrarse
  - Endpoint `GET /api/v1/auth/verify-email/{token}` - Verificar email
  - Endpoint `POST /api/v1/auth/resend-verification` - Reenviar email
  - Token expira en 24 horas
  - Email de bienvenida al verificar

- **Change Password**: Cambio de contrase\u00f1a para usuarios autenticados
  - Endpoint `PUT /api/v1/users/me/password` - Cambiar contrase\u00f1a
  - Requiere contrase\u00f1a actual para validaci\u00f3n
  - Invalidaci\u00f3n autom\u00e1tica de sesiones y tokens

- **Email Service**: Integraci\u00f3n con Resend
  - Emails transaccionales (verificaci\u00f3n, reset, bienvenida, confirmaci\u00f3n)
  - Templates HTML personalizados
  - Env\u00edo as\u00edncrono para no bloquear requests

- **Testing**: Script automatizado de pruebas
  - `test-reset-flow.sh` - Prueba completa del flujo de reset
  - Valida invalidaci\u00f3n de tokens antiguos
  - Valida funcionamiento de tokens nuevos

### \ud83d\udcdd Documentaci\u00f3n

- Actualizado `CLAUDE.md` con:
  - Documentaci\u00f3n completa del sistema de blacklist
  - Explicaci\u00f3n de la correcci\u00f3n aplicada
  - Ejemplos de flujos de seguridad
  - Secci\u00f3n de testing automatizado

- Actualizado `docs/openapi.yaml` con:
  - Endpoints de forgot-password y reset-password
  - Endpoints de verificaci\u00f3n de email
  - Endpoint de cambio de contrase\u00f1a
  - Documentaci\u00f3n del sistema de blacklist
  - Changelog en metadata

### \ud83d\udd12 Seguridad

- **Mejorada**: Invalidaci\u00f3n de tokens por timestamp
  - Tokens antiguos se invalidan correctamente
  - Tokens nuevos funcionan inmediatamente
  - No hay ventana de vulnerabilidad
  - TTL autom\u00e1tico de 24h en Redis

- **Mejorada**: Reset de contrase\u00f1a
  - Token de un solo uso
  - Expiraci\u00f3n en 1 hora
  - Invalidaci\u00f3n de todas las sesiones
  - Email de confirmaci\u00f3n

### \ud83d\udee0\ufe0f T\u00e9cnico

- Agregada dependencia circular controlada: `UserService` \u2192 `AuthService`
- M\u00e9todo `SetAuthService()` para inyecci\u00f3n de dependencia
- Refactorizado `BlacklistUser()` para usar TTL en lugar de timestamp futuro
- Mejorado manejo de errores en servicios de email

---

## [1.0.0] - 2024-11-15

### \ud83c\udf89 Release Inicial

#### \u2728 Caracter\u00edsticas

- **Autenticaci\u00f3n**
  - Registro de usuarios con validaci\u00f3n
  - Login con email/password
  - JWT con RS256 (asim\u00e9trico)
  - Access token (15 min) y Refresh token (7 d\u00edas)
  - Token rotation autom\u00e1tico
  - Logout con invalidaci\u00f3n de sesi\u00f3n

- **Autorizaci\u00f3n (RBAC)**
  - Sistema de roles por aplicaci\u00f3n
  - 3 roles predefinidos: user, moderator, admin
  - 14 permisos granulares
  - Auto-asignaci\u00f3n de rol "user" en registro
  - Middlewares de autorizaci\u00f3n
  - Gesti\u00f3n completa de roles (CRUD)

- **Seguridad**
  - Password hashing con Argon2id
  - Account locking (5 intentos \u2192 15 min)
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

#### \ud83d\udcdd Documentaci\u00f3n

- README.md completo
- ARCHITECTURE.md con diagramas
- RBAC_GUIDE.md detallado
- TESTING_RBAC.md paso a paso
- OpenAPI 3.0 specification
- Scripts de automatizaci\u00f3n

#### \ud83d\udee0\ufe0f Stack T\u00e9cnico

- Go 1.24
- Fiber v2 (web framework)
- PostgreSQL 16
- Redis 7
- JWT con RS256
- Argon2id para passwords
- Docker + Docker Compose

---

## Tipos de Cambios

- `\u2728 Agregado` - Nueva funcionalidad
- `\ud83d\udd27 Corregido` - Bug fix
- `\ud83d\udd12 Seguridad` - Mejora de seguridad
- `\ud83d\udcdd Documentaci\u00f3n` - Cambios en documentaci\u00f3n
- `\ud83d\udee0\ufe0f T\u00e9cnico` - Cambios t\u00e9cnicos internos
- `\u26a0\ufe0f Deprecado` - Funcionalidad que ser\u00e1 removida
- `\ud83d\uddd1\ufe0f Removido` - Funcionalidad removida
- `\ud83d\ude80 Performance` - Mejora de rendimiento

---

## Links

- [Repositorio](https://github.com/your-org/auth-service)
- [Documentaci\u00f3n](./CLAUDE.md)
- [Issues](https://github.com/your-org/auth-service/issues)
- [Roadmap](./ROADMAP.md)
