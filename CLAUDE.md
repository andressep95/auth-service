# Auth Service - Identity Provider Multi-Tenant

Sistema de autenticación y autorización empresarial diseñado para ecosistemas de microservicios con múltiples aplicaciones independientes.

---

## 📋 Índice de Documentación

### Flujos Principales

- [**Registro de Usuarios**](docs/registro.md) - Auto-detección de apps, templates dinámicos, verificación por email
- [**Login y Autenticación**](docs/login.md) - JWT dual-token, session management, token rotation, account locking

### Features del Sistema

_(En desarrollo)_

- Gestión de Sesiones
- Password Reset
- Multi-Tenancy
- RBAC (Roles y Permisos)

---

## 🎯 Descripción del Proyecto

**Auth Service** es un Identity Provider (IdP) multi-tenant que permite a múltiples aplicaciones web gestionar sus usuarios de forma aislada y segura. Cada aplicación puede tener sus propios usuarios, roles, permisos y tenants, con aislamiento completo de datos.

### Arquitectura

```
┌─────────────────┐
│   App Frontend  │ ──→ Origin-based auto-detection
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  Auth Service   │ ──→ Multi-tenant isolation
│  (Identity IdP) │ ──→ Dynamic templates
└────────┬────────┘ ──→ Session management
         │
    ┌────┴────┐
    ↓         ↓
┌────────┐ ┌────────┐
│PostgreSQL│ │ Redis  │
│ (Data)   │ │ (Cache)│
└──────────┘ └────────┘
```

### Casos de Uso

- **SaaS Multi-Tenant**: Múltiples clientes, cada uno con su app y usuarios aislados
- **Ecosistema de Microservicios**: Un IdP centralizado para N aplicaciones independientes
- **White-Label Applications**: Misma plataforma, diferentes brandings y bases de usuarios

---

## 🛠 Stack Tecnológico

| Categoría         | Tecnología             | Versión |
| ----------------- | ---------------------- | ------- |
| **Runtime**       | Go                     | 1.24+   |
| **Framework**     | Fiber                  | v2      |
| **Base de Datos** | PostgreSQL             | 16      |
| **Cache**         | Redis                  | 7       |
| **Templates**     | Go Templates           | -       |
| **Email**         | CloudCentinel (Resend) | -       |

### Estándares de Seguridad

| Componente           | Estándar Usado                  |
| -------------------- | ------------------------------- |
| **Password Hashing** | Argon2id (64MB, 3 iterations)   |
| **JWT Signing**      | RS256 (RSA 4096 bits)           |
| **Session Tokens**   | SHA-256 hashing                 |
| **Email Tokens**     | Cryptographically secure random |
| **CSRF Protection**  | Double Submit Cookie Pattern    |
| **SQL Injection**    | Prepared Statements (pgx)       |

### Planeados para Implementar

| Feature                  | Prioridad | Estándar de Referencia  |
| ------------------------ | --------- | ----------------------- |
| **OAuth2 Provider**      | Alta      | RFC 6749 (OAuth 2.0)    |
| **OpenID Connect**       | Alta      | OpenID Connect Core 1.0 |
| **MFA/2FA**              | Alta      | TOTP (RFC 6238)         |
| **Rate Limiting**        | Media     | Token Bucket Algorithm  |
| **Geolocation Tracking** | Baja      | MaxMind GeoIP2          |

---

## 🔒 Capas de Seguridad

### Comparación con OAuth2 y Keycloak

| Feature de Seguridad             | Auth Service | OAuth2 | Keycloak | Notas                                |
| -------------------------------- | ------------ | ------ | -------- | ------------------------------------ |
| **Autenticación**                |              |        |          |
| Password Authentication          | ✅           | ❌     | ✅       | OAuth delega, no autentica           |
| Social Login (OAuth2 Client)     | ⏳           | -      | ✅       | Infraestructura preparada            |
| Multi-Factor Auth (MFA)          | ⏳           | -      | ✅       | Campos en DB listos                  |
| Passwordless (Magic Links)       | ❌           | -      | ✅       | No planeado aún                      |
| **Autorización**                 |              |        |          |
| Role-Based Access Control (RBAC) | ✅           | -      | ✅       | 4 roles default por app              |
| Permission-Based Access          | ✅           | -      | ✅       | 14 permisos granulares               |
| OAuth2 Scopes                    | ⏳           | ✅     | ✅       | En diseño                            |
| Fine-Grained Permissions         | ⏳           | -      | ✅       | Planeado                             |
| **Tokens y Sesiones**            |              |        |          |
| JWT con RS256                    | ✅           | ✅     | ✅       | RSA 4096 bits                        |
| Access Token (short-lived)       | ✅           | ✅     | ✅       | 15 minutos                           |
| Refresh Token (long-lived)       | ✅           | ✅     | ✅       | 7 días con rotation                  |
| Token Blacklist                  | ✅           | -      | ✅       | Redis con invalidación por timestamp |
| Session Management               | ✅           | -      | ✅       | PostgreSQL + Redis                   |
| JWKS Endpoint                    | ✅           | ✅     | ✅       | `/.well-known/jwks.json`             |
| **Multi-Tenancy**                |              |        |          |
| App Isolation                    | ✅           | -      | ✅       | Constraint UNIQUE(app_id, email)     |
| Tenant dentro de Apps            | ✅           | -      | ✅       | Doble nivel de aislamiento           |
| Cross-Tenant Prevention          | ✅           | -      | ✅       | Queries siempre filtran por app_id   |
| **Seguridad de Passwords**       |              |        |          |
| Strong Hashing (Argon2)          | ✅           | -      | ✅       | 64MB memory, 3 iterations            |
| Password Strength Validation     | ✅           | -      | ✅       | 8+ chars, complejidad                |
| Password Reset Flow              | ✅           | -      | ✅       | Token 1h, un solo uso                |
| Password History                 | ❌           | -      | ✅       | No implementado                      |
| **Account Protection**           |              |        |          |
| Account Locking                  | ✅           | -      | ✅       | 5 intentos → 15 min bloqueo          |
| Email Verification               | ✅           | -      | ✅       | Token 24h                            |
| Suspicious Activity Detection    | ⏳           | -      | ✅       | IP tracking implementado             |
| **Standards Compliance**         |              |        |          |
| OAuth 2.0 Provider               | ⏳           | ✅     | ✅       | En diseño                            |
| OpenID Connect                   | ⏳           | -      | ✅       | Requiere OAuth2 primero              |
| SAML 2.0                         | ❌           | -      | ✅       | No planeado                          |
| **Infrastructure**               |              |        |          |
| Rate Limiting                    | ⏳           | -      | ✅       | Infraestructura preparada            |
| CORS Protection                  | ✅           | -      | ✅       | Configurable por entorno             |
| CSRF Protection                  | ✅           | -      | ✅       | Double Submit Cookie                 |
| Audit Logging                    | ⏳           | -      | ✅       | Tabla creada, pendiente integración  |
| **DevOps**                       |              |        |          |
| Docker Support                   | ✅           | ✅     | ✅       | Docker Compose completo              |
| Health Checks                    | ✅           | ✅     | ✅       | `/health` y `/ready`                 |
| Graceful Shutdown                | ✅           | ✅     | ✅       | SIGINT/SIGTERM handling              |
| Metrics (Prometheus)             | ⏳           | ✅     | ✅       | Planeado                             |

### Leyenda

- ✅ **Implementado** - Feature completamente funcional
- ⏳ **En desarrollo** - Infraestructura preparada o en progreso
- ❌ **No planeado** - No está en el roadmap actual

---

## 🚀 Roadmap hacia OAuth2/Keycloak Parity

### Fase 1: Fundamentos (COMPLETADA) ✅

- Multi-tenancy con aislamiento de apps
- RBAC completo con roles y permisos
- JWT con RS256 y JWKS endpoint
- Session management con blacklist
- Email verification y password reset
- CSRF protection

### Fase 2: OAuth2 Provider (EN PROGRESO) ⏳

- Authorization Code Flow
- Client Credentials Flow
- Refresh Token Flow
- Scope management
- Consent screens

### Fase 3: Seguridad Avanzada (PLANEADA)

- MFA/2FA con TOTP
- Social Login (Google, GitHub)
- Rate limiting activo
- Audit logging completo
- Suspicious activity detection

### Fase 4: Enterprise Features (FUTURO)

- OpenID Connect
- Fine-grained permissions
- Password history
- Session anomaly detection
- Metrics y observabilidad completa

---

## 📚 Documentación Extendida

Toda la documentación detallada de features se encuentra en la carpeta [`docs/`](docs/):

- Flujos de usuario (registro, login, reset, etc.)
- Arquitectura de features específicas
- Diagramas de flujo y tablas de estados
- Guías de integración

---

**Versión del Proyecto:** 1.5.0
**Última Actualización:** 2024-12-21
