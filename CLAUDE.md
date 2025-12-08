# Auth Service - Documentación Completa

## 📋 Índice

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Arquitectura](#arquitectura)
3. [Inicio Rápido](#inicio-rápido)
4. [Características](#características)
5. [API Endpoints](#api-endpoints)
6. [Seguridad](#seguridad)
7. [Configuración](#configuración)
8. [Desarrollo](#desarrollo)
9. [Testing](#testing)
10. [Deployment](#deployment)

---

## Resumen Ejecutivo

**Auth Service** es un microservicio de autenticación y autorización multi-tenant construido en Go con arquitectura limpia, diseñado para ser el Identity Provider de un ecosistema de microservicios donde múltiples aplicaciones independientes pueden registrarse y gestionar sus propios usuarios.

> 🔒 **Versión 1.5.0** - Sistema multi-tenant completo con gestión de aplicaciones independientes.
> Cada aplicación tiene su propio conjunto de usuarios, roles y permisos con aislamiento total.
> Incluye corrección crítica del sistema de token blacklist y session management completo.

### Tecnologías Core

- **Lenguaje**: Go 1.24
- **Framework Web**: Fiber v2
- **Base de Datos**: PostgreSQL 16 con soporte multi-tenant
- **Cache**: Redis 7 para token blacklist
- **Tokens**: JWT con RS256 (RSA) incluyendo app_id en claims
- **Password Hashing**: Argon2id
- **Containerización**: Docker + Docker Compose
- **Email Service**: CloudCentinel Email Service (AWS SES)

### Estado del Proyecto

✅ **Producción Ready** - Sistema multi-tenant completamente implementado
✅ **Multi-Tenancy** - Aislamiento completo de usuarios por aplicación (app_id)
✅ **App Management** - Gestión de aplicaciones independientes (super_admin)
✅ **Session Management** - Control completo de sesiones activas por usuario
✅ **Email Service** - Integrado con CloudCentinel Email Service (AWS SES)
✅ **Password Reset** - Flujo completo con invalidación de tokens por timestamp
✅ **Token Blacklist** - Sistema por timestamp funcionando correctamente
✅ **Social Login Ready** - Campos preparados para OAuth providers (google, github)
✅ **JWKS Endpoint** - Validación de tokens JWT por otros microservicios

**Última actualización:** v1.5.0 (2024-12-07)

---

## Arquitectura

### Arquitectura Multi-Tenant

El sistema implementa multi-tenancy a nivel de aplicación donde cada app opera de forma independiente:

**Modelo de Aislamiento:**
- Cada aplicación tiene un `app_id` único (UUID)
- Los usuarios se registran en una aplicación específica mediante `app_id` en el registro
- Un mismo email puede existir en múltiples aplicaciones con diferentes contraseñas
- Constraint de unicidad: `UNIQUE(app_id, email)` en tabla users
- Constraint para social login: `UNIQUE(app_id, provider, provider_id)`
- Búsqueda de usuarios siempre requiere `app_id + email`

**Aislamiento de Datos:**
- **Usuarios**: Campo `app_id` en tabla users, todas las consultas filtran por app_id
- **Sesiones**: Campo `app_id` en tabla sessions, aislamiento completo por aplicación
- **Roles**: Campo `app_id` en tabla roles, cada app tiene sus propios roles independientes
- **Permisos**: Campo `app_id` en tabla permissions
- **JWT tokens**: Incluyen `app_id` en claims para validación en otros microservicios

**Gestión de Aplicaciones:**
- Super Admin puede crear nuevas aplicaciones vía POST /api/v1/super-admin/apps
- Cada app tiene: id (UUID), name, client_id, description, timestamps
- Trigger automático crea 4 roles default por app: super_admin, admin, moderator, user
- Endpoint requiere `is_super_admin=true` en el usuario
- Listar apps: GET /api/v1/super-admin/apps
- Obtener app específica: GET /api/v1/super-admin/apps/:id

**Preparación para Social Login:**
- Campo `provider` en users: google, github, facebook, etc. (nullable)
- Campo `provider_id` en users: ID del usuario en el proveedor externo (nullable)
- Constraint único: `(app_id, provider, provider_id)`
- Password es opcional cuando provider != null (login con OAuth)
- Permite login híbrido: mismo usuario con password y social login

**Flujo Multi-Tenant:**
1. Super Admin crea nueva aplicación → app_id generado + 4 roles default
2. Usuario se registra con app_id específico → registro en esa app únicamente
3. Usuario hace login con app_id + email + password → token incluye app_id
4. Cada app tiene sus propios roles y permisos aislados

### Estructura del Proyecto

```
auth-service/
├── cmd/
│   └── main.go                 # Entry point
├── internal/
│   ├── config/                 # Configuración
│   ├── domain/                 # Entidades de negocio
│   ├── handler/                # HTTP handlers
│   │   └── middleware/         # Middlewares
│   ├── repository/             # Capa de datos
│   │   └── postgres/           # Implementación PostgreSQL
│   └── service/                # Lógica de negocio
├── pkg/
│   ├── hash/                   # Argon2 hashing
│   ├── jwt/                    # JWT service
│   └── validator/              # Validación
├── migrations/                 # SQL migrations
├── scripts/                    # Scripts de automatización
├── keys/                       # RSA keys (generadas)
└── docs/                       # Documentación adicional
```

### Capas de la Aplicación

```
┌─────────────────────────────────────┐
│         HTTP Layer (Fiber)          │
│  ┌──────────┐  ┌──────────────┐    │
│  │ Handlers │  │ Middlewares  │    │
│  └──────────┘  └──────────────┘    │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│        Service Layer (Business)     │
│  ┌──────────┐  ┌──────────────┐    │
│  │   Auth   │  │    Roles     │    │
│  │  Service │  │   Service    │    │
│  └──────────┘  └──────────────┘    │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│      Repository Layer (Data)        │
│  ┌──────────┐  ┌──────────────┐    │
│  │   User   │  │   Session    │    │
│  │   Repo   │  │    Repo      │    │
│  └──────────┘  └──────────────┘    │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│         PostgreSQL + Redis          │
└─────────────────────────────────────┘
```

### Flujo de Autenticación

```
1. Usuario → POST /auth/login
2. Validar credenciales (Argon2id)
3. Verificar cuenta no bloqueada
4. Obtener roles del usuario
5. Generar Access Token (15 min)
6. Generar Refresh Token (7 días)
7. Guardar sesión en DB (hash del refresh token)
8. Retornar tokens al cliente
```

---

## Inicio Rápido

### Prerequisitos

- Docker & Docker Compose
- Go 1.24+ (para desarrollo local)
- Make (opcional pero recomendado)

### Setup Automático (Recomendado)

```bash
# Clonar repositorio
git clone <repo-url>
cd auth-service

# Setup completo con un comando
make quickstart
```

Esto ejecuta automáticamente:
1. ✅ Genera claves RSA
2. ✅ Inicia servicios Docker (PostgreSQL, Redis, App)
3. ✅ Ejecuta migraciones
4. ✅ Crea usuario admin por defecto
5. ✅ Verifica que todo funcione

**Credenciales por defecto:**
- Email: `admin@test.com`
- Password: `Admin123!`

### Setup con Credenciales Personalizadas

```bash
make quickstart-custom
# Te pedirá: email, password, nombre, apellido
```

### Verificar Instalación

```bash
# Ver estado del sistema
make status

# Ver logs
make logs

# Login rápido con admin
make admin-login
```

---

## Características

### ✅ Implementadas

#### Multi-Tenancy
- ✅ Aislamiento completo de usuarios por app_id
- ✅ Mismo email puede existir en múltiples apps con diferentes passwords
- ✅ Gestión de aplicaciones (crear, listar, obtener por ID)
- ✅ Roles y permisos independientes por aplicación
- ✅ JWT tokens incluyen app_id en claims
- ✅ Super Admin puede gestionar todas las aplicaciones
- ✅ Trigger automático crea 4 roles default al crear app
- ✅ Constraint UNIQUE(app_id, email) y UNIQUE(app_id, provider, provider_id)

#### Autenticación
- ✅ Registro de usuarios por aplicación (requiere app_id)
- ✅ Login con email/password/app_id
- ✅ Refresh token rotation automática
- ✅ Logout con invalidación de sesión
- ✅ Account locking: 5 intentos fallidos → bloqueo 15 minutos
- ✅ Password hashing con Argon2id (64MB memory, 3 iterations)
- ✅ Email verification con token de 24h
- ✅ Password reset con token de 1h de un solo uso
- ✅ Cambio de contraseña con invalidación de sesiones
- ✅ Preparación para Social Login (provider, provider_id fields)

#### Autorización (RBAC)
- ✅ Sistema de roles por aplicación (multi-tenant)
- ✅ 4 roles predefinidos por app: super_admin, admin, moderator, user
- ✅ 14 permisos granulares
- ✅ Auto-asignación de rol "user" en registro (trigger)
- ✅ Middlewares de autorización (RequireAuth, RequireRole, RequirePermission)
- ✅ Gestión completa de roles (CRUD) por app_id
- ✅ Asignación/remoción de roles a usuarios
- ✅ Consulta de permisos efectivos del usuario

#### Tokens & Sesiones
- ✅ JWT con RS256 (asimétrico, RSA 4096 bits)
- ✅ Access token: 15 minutos de duración
- ✅ Refresh token: 7 días de duración
- ✅ Token rotation en cada refresh (invalidación del anterior)
- ✅ Sesiones almacenadas en PostgreSQL con app_id
- ✅ Refresh tokens hasheados (SHA-256) en DB
- ✅ Session Management: listar sesiones activas del usuario
- ✅ Cierre de sesión específica por ID
- ✅ Cierre de todas las sesiones (con opción exclude_current)
- ✅ Metadata de sesiones: IP, User-Agent, timestamps
- ✅ JWKS endpoint (/.well-known/jwks.json) para validación por otros servicios

#### Seguridad
- ✅ CORS configurable por variables de entorno
- ✅ Password strength validation (8+ chars, mayúscula, minúscula, número, especial)
- ✅ Token Blacklist en Redis con invalidación por timestamp
- ✅ Invalidación automática de tokens al cambiar/resetear contraseña
- ✅ Rate limiting ready (infraestructura preparada)
- ✅ HTTPS ready
- ✅ Audit logs table (estructura creada, integración pendiente)
- ✅ Argon2id para password hashing
- ✅ Token rotation en refresh para prevenir replay attacks

#### Infraestructura
- ✅ Docker Compose setup multi-contenedor
- ✅ Health checks (/health básico, /ready con DB+Redis)
- ✅ Graceful shutdown con señales SIGINT/SIGTERM
- ✅ Connection pooling optimizado (25 max open, 5 idle, 5min lifetime)
- ✅ Migraciones SQL versionadas (001_initial.sql consolidado)
- ✅ Scripts de automatización (setup, keys, admin creation)
- ✅ Email service con CloudCentinel (AWS SES) integrado

### ⏳ Pendientes

#### Alta Prioridad
- ⏳ MFA/2FA con TOTP (campos preparados en DB)
- ⏳ Rate limiting activo por IP y por usuario
- ⏳ Implementar OAuth2 social login (infraestructura ya preparada)

#### Media Prioridad
- ⏳ Audit logging activo (tabla existe, falta integración)
- ⏳ Session management UI/Dashboard
- ⏳ Rotación automática de claves RSA
- ⏳ Métricas y observabilidad (Prometheus/Grafana)

#### Baja Prioridad
- ⏳ OAuth2 provider (este servicio como IdP para otros)
- ⏳ Recuperación de cuenta por SMS
- ⏳ Geolocalización de sesiones

---

## API Endpoints

Ver `docs/openapi.yaml` para especificación completa de la API.

### Setup y Health

#### POST /api/v1/setup/super-admin
Crea el primer super administrador del sistema (solo una vez).
- **Seguridad**: Endpoint público, bloqueado después del primer uso
- **Request**: email, password, first_name, last_name
- **Response**: 201 Created con datos del super admin
- **Uso**: Llamar inmediatamente después del deployment inicial

#### GET /health
Health check básico - verifica que el servicio esté corriendo.
- **Response**: 200 OK con status y timestamp

#### GET /ready
Readiness check - verifica conexión a PostgreSQL y Redis.
- **Response**: 200 OK con estado de database y redis

#### GET /.well-known/jwks.json
JSON Web Key Set para validación de tokens JWT por otros microservicios.
- **Formato**: Array de claves públicas en formato JWK (kty, use, kid, alg, n, e)
- **Uso**: Integración con API Gateways y validación de tokens distribuida

### Autenticación (Público)

#### POST /api/v1/auth/register
Registra un nuevo usuario en una aplicación específica.
- **Requiere**: app_id (UUID), email, password, first_name, last_name, phone_number (opcional)
- **Validación**: Password mínimo 8 caracteres con mayúscula, minúscula, número y carácter especial
- **Response**: 201 Created con datos del usuario
- **Auto-asignación**: Rol "user" asignado automáticamente
- **Multi-tenant**: Usuario aislado por app_id

#### POST /api/v1/auth/login
Autentica usuario y retorna tokens JWT.
- **Requiere**: email, password, app_id (UUID)
- **Response**: 200 OK con access_token (15 min), refresh_token (7 días), user
- **Token tipo**: Bearer con RS256
- **Claims**: Incluye user_id, email, roles, app_id
- **Account locking**: 5 intentos fallidos → bloqueo 15 minutos
- **Multi-tenant**: Login específico por aplicación (app_id)

#### POST /api/v1/auth/refresh
Renueva access token usando refresh token.
- **Requiere**: refresh_token
- **Response**: 200 OK con nuevos access_token y refresh_token
- **Token rotation**: Refresh token anterior se invalida automáticamente
- **Seguridad**: Hash SHA-256 del refresh token almacenado en DB

#### POST /api/v1/auth/logout
Cierra sesión e invalida refresh token.
- **Requiere**: refresh_token
- **Response**: 200 OK
- **Efecto**: Elimina sesión de DB y refresh token

#### POST /api/v1/auth/forgot-password
Solicita reset de contraseña vía email.
- **Requiere**: email
- **Response**: 200 OK (siempre, por seguridad)
- **Token**: 1 hora de validez, enviado por email
- **Seguridad**: No revela si el email existe o no

#### POST /api/v1/auth/reset-password
Resetea contraseña usando token del email.
- **Requiere**: token, new_password
- **Response**: 200 OK
- **Seguridad**: Token de un solo uso, expira en 1h, cierra todas las sesiones, invalida todos los tokens emitidos antes del reset
- **Email**: Confirmación enviada automáticamente

#### GET /api/v1/auth/verify-email/:token
Verifica email del usuario con token.
- **Requiere**: token en path
- **Response**: 200 OK
- **Token**: 24 horas de validez

#### POST /api/v1/auth/resend-verification
Reenvía email de verificación.
- **Requiere**: email
- **Response**: 200 OK
- **Condición**: Solo si email no verificado

### Usuario (Autenticado)

Todos los endpoints requieren header `Authorization: Bearer <access_token>`

#### GET /api/v1/users/me
Obtiene perfil del usuario actual.
- **Response**: Datos completos del usuario incluyendo app_id, provider, is_super_admin

#### PUT /api/v1/users/me
Actualiza perfil del usuario actual.
- **Campos**: first_name, last_name, phone_number

#### PUT /api/v1/users/me/password
Cambia contraseña del usuario autenticado.
- **Requiere**: old_password, new_password
- **Seguridad**: Cierra todas las sesiones, invalida todos los tokens antiguos por timestamp
- **Re-autenticación**: Usuario debe hacer login nuevamente

#### GET /api/v1/users/me/roles
Lista roles del usuario actual en su aplicación.
- **Response**: Array de roles con detalles completos

#### GET /api/v1/users/me/permissions
Lista permisos efectivos del usuario (agregados de todos sus roles).
- **Response**: Array de permisos con resource, action, description

#### GET /api/v1/users/me/sessions
Lista todas las sesiones activas del usuario.
- **Response**: Array de sesiones con id, user_agent, ip_address, expires_at, created_at, is_current
- **Uso**: Ver dónde está logueado, detectar sesiones sospechosas

#### DELETE /api/v1/users/me/sessions
Cierra todas las sesiones del usuario.
- **Parámetro query**: exclude_current (boolean, default: false)
- **Response**: 200 OK con número de sesiones cerradas
- **Limitación**: Si exclude_current=true requiere session_id en contexto

#### DELETE /api/v1/users/me/sessions/:id
Cierra una sesión específica por ID.
- **Requiere**: id (UUID) en path
- **Response**: 200 OK
- **Seguridad**: Solo puede cerrar sus propias sesiones (403 si intenta cerrar de otro usuario)

### Administración (Requiere rol admin)

#### GET /api/v1/admin/users
Lista usuarios con paginación y búsqueda.
- **Parámetros**: page (default: 1), limit (default: 20, max: 100), search (email/nombre/apellido)
- **Response**: Array de usuarios con roles asignados + metadata de paginación

#### GET /api/v1/admin/users/:id
Obtiene usuario específico por ID.
- **Response**: Usuario con roles asignados

#### GET /api/v1/admin/roles
Lista todos los roles de una aplicación.
- **Requiere query**: app_id (UUID)
- **Response**: Array de roles con permisos

#### POST /api/v1/admin/roles
Crea un nuevo rol en una aplicación.
- **Requiere**: app_id (UUID), name (snake_case), description
- **Constraint**: UNIQUE(app_id, name)

#### GET /api/v1/admin/roles/:id
Obtiene detalles de un rol específico.

#### PUT /api/v1/admin/roles/:id
Actualiza descripción de un rol.
- **Nota**: No se puede cambiar el nombre del rol

#### DELETE /api/v1/admin/roles/:id
Elimina un rol del sistema.
- **Restricción**: No se puede eliminar rol con usuarios asignados

#### GET /api/v1/admin/roles/:id/permissions
Lista permisos de un rol específico.

#### GET /api/v1/admin/users/:userId/roles
Lista roles de un usuario específico.

#### POST /api/v1/admin/users/:userId/roles/:roleId
Asigna un rol a un usuario.
- **Idempotente**: No falla si el usuario ya tiene el rol

#### DELETE /api/v1/admin/users/:userId/roles/:roleId
Remueve un rol de un usuario.

### Super Admin (Requiere is_super_admin=true)

#### POST /api/v1/super-admin/apps
Crea una nueva aplicación en el sistema multi-tenant.
- **Requiere**: name (2-100 chars), description (opcional, max 500 chars)
- **Response**: 201 Created con app (id, name, client_id, description, timestamps)
- **Auto-creación**: Trigger crea 4 roles default (super_admin, admin, moderator, user) con permisos

#### GET /api/v1/super-admin/apps
Lista todas las aplicaciones registradas.
- **Response**: Array de apps con conteo total

#### GET /api/v1/super-admin/apps/:id
Obtiene aplicación específica por ID.
- **Requiere**: id (UUID) en path
- **Response**: Detalles completos de la aplicación

---

## Seguridad

### Password Hashing

**Algoritmo:** Argon2id (estándar de la industria para password hashing)

**Configuración:**
- Memory: 64 MB (65536 KB)
- Iterations: 3
- Parallelism: 2 threads
- Salt: 16 bytes (generado aleatoriamente por usuario)
- Key length: 32 bytes
- Formato almacenado: `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>`

### JWT Tokens

**Algoritmo:** RS256 (RSA con SHA-256, asimétrico)
**Longitud clave:** RSA 4096 bits

**Access Token:**
- Duración: 15 minutos
- Claims: iss (auth-service), sub (user_id), exp, iat, jti, uid, email, roles, app_id, type (access)
- Uso: Autenticación en requests API

**Refresh Token:**
- Duración: 7 días (168 horas)
- Claims: iss, sub (user_id), exp, iat, jti, type (refresh)
- Almacenamiento: Hash SHA-256 en tabla sessions de PostgreSQL
- Rotación: Automática en cada uso (token anterior se invalida)
- Uso: Obtener nuevos access tokens sin re-login

**JWKS Endpoint:**
- Ubicación: `/.well-known/jwks.json`
- Formato: JSON Web Key Set con claves públicas
- Uso: Otros microservicios pueden validar tokens sin compartir clave privada

### Account Locking

**Política de intentos fallidos:**
- Máximo: 5 intentos consecutivos fallidos
- Duración de bloqueo: 15 minutos automático
- Reset del contador: Login exitoso o desbloqueo manual
- Campo DB: `failed_login_attempts`, `account_locked_until`
- Desbloqueo manual: Admin puede resetear con UPDATE directo en DB

### CORS

**Configuración:**
- Variable de entorno: `CORS_ALLOWED_ORIGINS` (lista separada por comas)
- Desarrollo: `http://localhost:3000,http://localhost:8080`
- Producción: Lista explícita de dominios permitidos
- **Importante**: Nunca usar wildcard (*) en producción con credentials
- Validación: En cada request HTTP

### Session Security

**Características de seguridad:**
- Refresh tokens hasheados con SHA-256 antes de almacenar
- Token rotation automática en cada refresh (previene replay attacks)
- Expiración automática: 7 días desde creación
- Limpieza automática: Sesiones expiradas eliminadas por índice
- Metadata tracking: IP address, User-Agent (opcional)
- App isolation: Campo `app_id` en sesiones
- Token Blacklist: Sistema de dos niveles (individual + por timestamp)
- Invalidación masiva: Al cambiar/resetear contraseña

### Token Blacklist (Redis)

**Sistema de Invalidación por Timestamp (v1.5):**

Implementa blacklist de dos niveles para máxima seguridad:

**Nivel 1 - Tokens individuales:**
- Key Redis: `blacklist:token:<sha256_hash>`
- Valor: "1"
- TTL: Hasta expiración natural del token
- Uso: Logout específico

**Nivel 2 - Invalidación por usuario:**
- Key Redis: `blacklist:user:<user_id>`
- Valor: timestamp_unix de invalidación
- TTL: 24 horas
- Uso: Cambio/reset de contraseña

**Lógica de validación:**
1. Extraer `IssuedAt` (iat) del token JWT
2. Verificar si hash del token está en blacklist individual → RECHAZAR
3. Obtener timestamp de invalidación de `blacklist:user:<user_id>`
4. Si `token.IssuedAt < invalidation_timestamp` → RECHAZAR
5. Si `token.IssuedAt >= invalidation_timestamp` → ACEPTAR
6. Si pasa todos los checks → Token válido

**Beneficios del sistema:**
- ✅ Invalida todos los tokens emitidos ANTES de cambio de contraseña
- ✅ Permite nuevos tokens emitidos DESPUÉS del cambio
- ✅ Evita bloqueos permanentes del usuario
- ✅ Auto-limpieza con TTL de Redis
- ✅ Performance: O(1) lookup en Redis

**Flujo típico:**
1. 10:00 - Login → Token A (IssuedAt: 10:00)
2. 10:30 - Reset password → Blacklist timestamp: 10:30, todas las sesiones cerradas
3. 10:31 - Token A usado → RECHAZADO (10:00 < 10:30)
4. 10:32 - Nuevo login → Token B (IssuedAt: 10:32)
5. 10:33 - Token B usado → ACEPTADO (10:32 >= 10:30)

---

## Configuración

### Variables de Entorno

**Server:**
- `SERVER_PORT`: Puerto HTTP (default: 8080)
- `ENVIRONMENT`: development | staging | production

**Database (PostgreSQL):**
- `DB_HOST`: Hostname (default: postgres para Docker)
- `DB_PORT`: Puerto (default: 5432)
- `DB_USER`: Usuario de la base de datos
- `DB_PASSWORD`: Contraseña (⚠️ usar secrets en producción)
- `DB_NAME`: Nombre de la base de datos (default: authdb)
- `DB_SSLMODE`: disable | require | verify-ca | verify-full

**Redis:**
- `REDIS_HOST`: Hostname (default: redis para Docker)
- `REDIS_PORT`: Puerto (default: 6379)
- `REDIS_PASSWORD`: Contraseña (vacío para dev)
- `REDIS_DB`: Número de DB (default: 0)

**JWT:**
- `JWT_PRIVATE_KEY_PATH`: Path a clave privada RSA (default: ./keys/private.pem)
- `JWT_PUBLIC_KEY_PATH`: Path a clave pública RSA (default: ./keys/public.pem)
- `JWT_ACCESS_EXPIRY`: Duración access token (default: 15m)
- `JWT_REFRESH_EXPIRY`: Duración refresh token (default: 168h)
- `JWT_ISSUER`: Issuer del token (default: auth-service)

**Auth:**
- `AUTH_MAX_FAILED_LOGINS`: Máximo intentos fallidos antes de bloquear (default: 5)
- `AUTH_LOCK_DURATION`: Duración del bloqueo (default: 15m)

**CORS:**
- `CORS_ALLOWED_ORIGINS`: Lista de orígenes permitidos separados por coma

**Email (CloudCentinel):**
- `EMAIL_SERVICE_URL`: URL del servicio de email (default: https://api.cloudcentinel.com/email/send)
- `EMAIL_ENABLED`: Habilitar/deshabilitar servicio de email (default: true)
- `EMAIL_TIMEOUT`: Timeout para requests de email (default: 10s)

**Nota:** Las URLs de verificación/reset y el remitente se configuran en el email-service, no aquí.

### Generar Claves RSA

**Automático (recomendado):**
- Comando: `make keys`
- Genera: RSA 4096 bits en ./keys/private.pem y ./keys/public.pem
- Permisos: 600 (private), 644 (public)

**Manual:**
- Generar privada: `openssl genrsa -out keys/private.pem 4096`
- Extraer pública: `openssl rsa -in keys/private.pem -pubout -out keys/public.pem`
- Permisos: `chmod 600 keys/private.pem && chmod 644 keys/public.pem`
- **Importante**: Nunca commitear claves en git (ya está en .gitignore)

---

## Desarrollo

### Comandos Make

**Setup completo:**
- `make quickstart` - Setup automático con credenciales por defecto (admin@test.com / Admin123!)
- `make quickstart-custom` - Setup con credenciales personalizadas (interactivo)
  - Ejecuta: generación de claves, inicio de Docker, migraciones, creación de super admin

**Desarrollo:**
- `make build` - Compilar binario Go
- `make run` - Ejecutar aplicación
- `make dev` - Setup entorno de desarrollo completo

**Docker:**
- `make docker-up` - Iniciar PostgreSQL, Redis y auth-service
- `make docker-down` - Detener y remover contenedores
- `make docker-logs` - Ver logs de todos los servicios
- `make logs` - Ver logs solo de auth-service

**Base de datos:**
- `make migrate` - Ejecutar migraciones SQL (migrations/001_initial.sql)
- `make db-status` - Ver estado de conexión DB
- `make db-reset` - ⚠️ Resetear DB completamente (borra todos los datos)

**Gestión:**
- `make status` - Estado general del sistema (servicios, DB, Redis)
- `make stop` - Detener todos los servicios
- `make restart` - Reiniciar todos los servicios
- `make keys` - Generar claves RSA

**Utilidades:**
- `make admin-login` - Login rápido con credenciales de admin (retorna token)
- `make create-admin` - Promover usuario existente a admin
- `make help` - Ver lista completa de comandos

### Flujo de Desarrollo

**Setup inicial:**
1. Clonar repositorio
2. Ejecutar `make quickstart` o `make quickstart-custom`
3. Verificar con `make status`

**Desarrollo activo:**
1. Iniciar servicios: `make docker-up`
2. Aplicar migraciones: `make migrate`
3. Compilar: `make build`
4. Ejecutar: `make run`
5. Probar: `curl http://localhost:8080/health`

**Hot Reload (opcional):**
- Instalar Air: `go install github.com/cosmtrek/air@latest`
- Ejecutar: `air` (recarga automática en cambios de código)

---

## Testing

### Scripts de Testing

**test-reset-flow.sh**
- Script automatizado para probar flujo completo de reset de contraseña
- Valida: Registro → Login → Reset → Token invalidation → Nuevo login
- Verifica que tokens antiguos se invaliden y nuevos tokens funcionen
- Confirma que contraseña vieja sea rechazada
- Ejecutar: `./test-reset-flow.sh`

**Puntos de validación:**
1. Registro de usuario exitoso
2. Login inicial con contraseña original
3. Token original funciona para requests autenticados
4. Solicitud de reset de contraseña
5. Reset ejecutado correctamente
6. Token original INVALIDADO (debe fallar con 401)
7. Login con nueva contraseña funciona
8. Nuevo token FUNCIONA correctamente
9. Contraseña vieja rechazada

### Testing Manual

**Documentación completa:**
- Ver `TESTING_RBAC.md` para guía detallada de testing de roles y permisos
- Ver `docs/openapi.yaml` para especificación completa de endpoints

**Flujo básico de testing:**
1. Registrar usuario con POST /api/v1/auth/register (requiere app_id, email, password, first_name, last_name)
2. Login con POST /api/v1/auth/login (requiere email, password, app_id)
3. Usar access_token en header `Authorization: Bearer <token>`
4. Probar endpoints autenticados (GET /api/v1/users/me, etc.)
5. Ver roles con GET /api/v1/users/me/roles
6. Ver permisos con GET /api/v1/users/me/permissions

**Testing Multi-Tenant:**
1. Crear super admin con POST /api/v1/setup/super-admin
2. Crear aplicación 1 con POST /api/v1/super-admin/apps
3. Crear aplicación 2 con POST /api/v1/super-admin/apps
4. Registrar mismo email en ambas apps con diferentes passwords
5. Verificar aislamiento completo (diferentes user_id, roles, sesiones)

### Herramientas de Testing

**cURL:**
- Testing directo desde terminal
- Útil para scripts automatizados
- Ver ejemplos en `TESTING_RBAC.md`

**Postman:**
- Importar colección desde `docs/postman_collection.json` (si existe)
- Permite guardar environments con tokens
- Testing interactivo de la API

**Herramientas recomendadas:**
- jq: Parsear respuestas JSON
- httpie: Alternativa más amigable a cURL
- Insomnia: Alternativa a Postman

---

## Deployment

### Docker Compose (Staging/Producción)

**Archivo:** `docker-compose.prod.yml` (si existe)
**Comando:** `docker-compose -f docker-compose.prod.yml up -d`

**Servicios incluidos:**
- auth-service (aplicación Go)
- PostgreSQL 16 con persistencia
- Redis 7 para blacklist

### Kubernetes (Producción)

**Manifests:** Ver directorio `k8s/` (si existe)

**Componentes recomendados:**
- Deployment con 3+ replicas para HA
- Service tipo ClusterIP
- Ingress con TLS/HTTPS
- ConfigMap para configuración no sensible
- Secret para credenciales (DB_PASSWORD, REDIS_PASSWORD, JWT keys)
- PersistentVolumeClaim para PostgreSQL data
- HorizontalPodAutoscaler basado en CPU/memoria

### Consideraciones de Producción

**1. Base de Datos:**
- Usar PostgreSQL managed (AWS RDS, GCP Cloud SQL, Azure Database)
- Habilitar backups automáticos diarios con retención de 7-30 días
- Configurar read replicas para escalabilidad de lectura
- Habilitar SSL/TLS (DB_SSLMODE=require)
- Connection pooling ya configurado (25 max open, 5 idle)

**2. Redis:**
- Usar Redis managed (AWS ElastiCache, GCP Memorystore, Azure Cache)
- Cluster mode para alta disponibilidad
- Persistence habilitada (AOF o RDB)
- Maxmemory policy: allkeys-lru para auto-cleanup

**3. Claves RSA:**
- Rotar claves cada 90-180 días
- Almacenar en secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager)
- Nunca commitear en git (.gitignore ya configurado)
- Generar claves de 4096 bits mínimo

**4. Logs y Observabilidad:**
- Centralizar logs con ELK Stack, Datadog, CloudWatch, o Loki
- Structured logging en formato JSON
- Log rotation automático
- Niveles: ERROR, WARN, INFO (no DEBUG en producción)

**5. Monitoring y Alertas:**
- Métricas con Prometheus + Grafana
- Health checks en /health y /ready para load balancer
- Alertas para: CPU > 80%, memoria > 85%, errores > 5%, DB conexiones > 90%
- Uptime monitoring externo (Pingdom, UptimeRobot)

**6. Seguridad:**
- HTTPS obligatorio (TLS 1.2+)
- Rate limiting activo por IP (nginx, Kong, API Gateway)
- WAF (Web Application Firewall) habilitado
- DDoS protection en capa de red
- Firewall rules: Solo puertos 80/443 expuestos
- Secrets rotation periódica

**7. Escalabilidad:**
- Stateless design permite horizontal scaling
- Redis para estado compartido (blacklist)
- Connection pooling configurado
- Consider CDN para assets estáticos

---

## Troubleshooting

### CORS Error

**Síntoma:** Error de CORS en navegador al hacer requests desde frontend

**Causas:**
- `CORS_ALLOWED_ORIGINS` no incluye el origen del frontend
- Origen mal formado (sin protocolo o con trailing slash)

**Solución:**
1. Verificar variable de entorno `CORS_ALLOWED_ORIGINS` incluye origen exacto
2. Formato correcto: `http://localhost:3000,https://app.example.com` (sin trailing slash)
3. Reiniciar servicio con `make restart`

### Database Connection Failed

**Síntoma:** Servicio no inicia o falla en /ready endpoint

**Causas:**
- PostgreSQL no corriendo
- Credenciales incorrectas
- Network issues en Docker

**Solución:**
1. Verificar PostgreSQL corriendo: `docker-compose ps postgres`
2. Ver logs de PostgreSQL: `docker-compose logs postgres`
3. Reiniciar PostgreSQL: `docker-compose restart postgres`
4. Verificar variables: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
5. Ping manual desde contenedor: `docker-compose exec auth-service ping postgres`

### Invalid Token / 401 Unauthorized

**Síntoma:** Requests autenticados rechazan con 401

**Causas comunes:**
1. Access token expirado (duración: 15 minutos)
2. Claves RSA cambiaron (se regeneraron después de generar el token)
3. Token type incorrecto (usando refresh token en lugar de access)
4. Usuario en blacklist por cambio de contraseña
5. Sesión eliminada

**Solución:**
1. Verificar expiración del token (claim `exp`)
2. Hacer refresh con POST /api/v1/auth/refresh usando refresh_token
3. Si refresh falla, hacer re-login con POST /api/v1/auth/login
4. Verificar claves RSA no cambiaron: `ls -la keys/`

### Account Locked

**Síntoma:** Login rechazado con "Account locked" o 423 status

**Causas:**
- 5 intentos fallidos de login consecutivos

**Solución:**
1. Esperar 15 minutos (desbloqueo automático)
2. Desbloqueo manual por admin:
   - Conectar a DB: `docker-compose exec postgres psql -U auth -d authdb`
   - Ejecutar: `UPDATE users SET failed_login_attempts=0, account_locked_until=NULL WHERE email='user@example.com';`
3. Verificar desbloqueo: `SELECT email, failed_login_attempts, account_locked_until FROM users WHERE email='user@example.com';`

### Redis Connection Failed

**Síntoma:** Token blacklist no funciona, errores de Redis en logs

**Solución:**
1. Verificar Redis corriendo: `docker-compose ps redis`
2. Ver logs: `docker-compose logs redis`
3. Reiniciar: `docker-compose restart redis`
4. Test manual: `docker-compose exec redis redis-cli PING` (debe retornar PONG)

### Migration Failed

**Síntoma:** Errores al ejecutar `make migrate`

**Causas:**
- Migraciones ya aplicadas
- Cambios manuales en DB

**Solución:**
1. Verificar estado de migraciones en tabla `schema_migrations` (si existe)
2. Ver último error en logs de PostgreSQL
3. Para desarrollo: `make db-reset` (⚠️ borra todos los datos)
4. Re-aplicar: `make migrate`

---

## Recursos Adicionales

### Documentación Principal

- `README.md` - Overview general y quick start
- `CLAUDE.md` - Este documento (documentación central completa)
- `CHANGELOG.md` - Historial de versiones y cambios (si existe)

### Documentación Técnica

- `docs/architecture.md` - Arquitectura detallada y diagramas del sistema (si existe)
- `docs/sequence-diagrams.md` - Diagramas de secuencia Mermaid de flujos principales (si existe)
- `docs/roadmap.md` - Plan de desarrollo y features pendientes (si existe)
- `docs/openapi.yaml` - **Especificación completa de la API (OpenAPI 3.0)** - Referencia principal

### Scripts de Automatización

- `scripts/full-setup.sh` - Setup automatizado completo (claves RSA + Docker + migraciones + super admin)
- `scripts/generate-keys.sh` - Generación de claves RSA 4096 bits
- `scripts/create-first-admin.sh` - Creación de super administrador inicial
- `test-reset-flow.sh` - Testing automatizado de flujo de reset de contraseña

### Migraciones SQL

**Estructura consolidada:**
- `migrations/001_initial.sql` - **Schema completo del sistema** (tablas, índices, constraints, triggers, roles default)
  - Incluye: apps, users, roles, permissions, role_permissions, user_roles, sessions
  - 4 roles default por app: super_admin, admin, moderator, user
  - 14 permisos granulares
  - Triggers de auto-asignación de roles
  - Índices optimizados para performance

**Nota:** Todas las migraciones futuras deben ser archivos separados (002, 003, etc.) para modificaciones incrementales

---

## Contacto y Soporte

**Repositorio:** [Especificar URL de GitHub]
**Documentación:** Ver carpeta `docs/`
**Issues:** [Especificar URL de GitHub Issues]

---

## Licencia

[Especificar licencia del proyecto]

---

## Historial de Correcciones y Mejoras

### Mejoras de Código y Seguridad Aplicadas

**cmd/main.go (4 issues corregidos):**
1. Log Injection (CWE-117): Sanitización de mensajes de error en logs
2. Error Handling en Goroutine: Uso de stop() para shutdown graceful
3. Resource Cleanup: Verificación de errores al cerrar conexiones
4. Connection Pooling: Configurado (25 max open, 5 idle, 5min lifetime)

**internal/config/config.go (3 mejoras):**
1. Error Handling: Logging de warnings en parseo de int/duration
2. Log Injection: No exponer valores inválidos en logs
3. SafeDSN Method: Agregado para logging sin password

**internal/domain/ (3 mejoras):**
1. Documentación: Agregados comentarios GoDoc a structs públicos
2. Naming Clarity: RefreshToken renombrado a RefreshTokenHash
3. Validation Tags: Agregadas tags de validación a structs

**Seguridad de Scripts:**
- SQL Injection: Scripts bash necesitan usar parámetros preparados
- Exposición de Credenciales: Passwords/tokens no deben mostrarse en output
- Error Handling: Comandos OpenSSL necesitan validación de errores

**Recomendaciones Pendientes:**
- Implementar rate limiting activo por IP y por usuario
- Agregar audit logging para acciones sensibles
- Implementar CSRF protection si se usa en navegadores
- Validación más estricta de UUIDs en handlers
- Usar secrets manager en producción para credenciales
- Rotación periódica de claves RSA (cada 90-180 días)

### Referencias de Seguridad

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Best Practices](https://github.com/OWASP/Go-SCP)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

## Corrección Crítica: Token Blacklist

### v1.1.0 - Sistema de Invalidación por Timestamp (2024-11-30)

**Problema Identificado:**
Después de resetear contraseña, el usuario no podía hacer login nuevamente. Todos los tokens nuevos eran rechazados con 401.

**Causa Raíz:**
El sistema guardaba un timestamp FUTURO (NOW + 24h) en la blacklist de Redis, invalidando TODOS los tokens incluyendo los emitidos después del reset.

**Solución Aplicada:**
- Cambio en `pkg/blacklist/blacklist.go`: Firma modificada de `until time.Time` a `ttl time.Duration`
- Guardar timestamp ACTUAL como punto de invalidación en lugar de timestamp futuro
- Tokens emitidos ANTES del timestamp → RECHAZADOS
- Tokens emitidos DESPUÉS del timestamp → ACEPTADOS

**Archivos Modificados:**
1. `pkg/blacklist/blacklist.go` - Lógica de blacklist corregida
2. `internal/service/auth_service.go` - Pasar TTL en lugar de timestamp
3. `internal/service/user_service.go` - Usar InvalidateAllUserSessions
4. `cmd/main.go` - Dependencia UserService → AuthService
5. `test-reset-flow.sh` - Script de testing automatizado

**Beneficios de la Corrección:**
- ✅ Tokens antiguos se invalidan correctamente
- ✅ Nuevos tokens funcionan inmediatamente
- ✅ Usuario puede hacer login después del reset
- ✅ Mantiene todas las garantías de seguridad
- ✅ Auto-limpieza con TTL de Redis (24h)

**Verificación:**
Script `test-reset-flow.sh` valida el flujo completo: Registro → Login → Reset → Invalidación → Nuevo Login

---

**Última actualización:** v1.5.0 (2024-12-07)
**Sistema:** Multi-tenant completo con gestión de aplicaciones independientes
