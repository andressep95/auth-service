# Arquitectura y Flujos del Auth Service

## 📋 Tabla de Contenidos

1. [Casos de Uso](#casos-de-uso)
2. [Diagramas de Secuencia](#diagramas-de-secuencia)
3. [Funcionalidades Implementadas vs Pendientes](#funcionalidades-implementadas-vs-pendientes)
4. [Modelo de Datos](#modelo-de-datos)
5. [Seguridad](#seguridad)

---

## Casos de Uso

### ✅ Implementados

| Caso de Uso | Descripción | Endpoint |
|-------------|-------------|----------|
| **UC-01: Registro de Usuario** | Usuario nuevo se registra en el sistema | `POST /api/v1/auth/register` |
| **UC-02: Login** | Usuario autentica y obtiene tokens JWT | `POST /api/v1/auth/login` |
| **UC-03: Refresh Token** | Usuario renueva su access token sin re-autenticar | `POST /api/v1/auth/refresh` |
| **UC-04: Logout** | Usuario cierra sesión e invalida su refresh token | `POST /api/v1/auth/logout` |
| **UC-05: Obtener Perfil** | Usuario consulta su propia información | `GET /api/v1/users/me` |
| **UC-06: Health Check** | Sistema verifica estado de salud | `GET /health`, `GET /ready` |

### ⏳ Pendientes (según README.md original)

| Caso de Uso | Descripción | Endpoint Propuesto | Prioridad |
|-------------|-------------|-------------------|-----------|
| **UC-07: Verificación de Email** | Usuario verifica su email mediante token | `GET /api/v1/auth/verify-email/:token` | 🔴 Alta |
| **UC-08: Solicitar Reset Password** | Usuario solicita resetear su contraseña | `POST /api/v1/auth/forgot-password` | 🔴 Alta |
| **UC-09: Reset Password** | Usuario resetea su contraseña con token | `POST /api/v1/auth/reset-password` | 🔴 Alta |
| **UC-10: Setup MFA** | Usuario configura autenticación de dos factores | `POST /api/v1/auth/mfa/setup` | 🟡 Media |
| **UC-11: Verify MFA** | Usuario verifica código MFA durante login | `POST /api/v1/auth/mfa/verify` | 🟡 Media |
| **UC-12: Disable MFA** | Usuario desactiva MFA | `DELETE /api/v1/auth/mfa` | 🟡 Media |
| **UC-13: JWKS Endpoint** | Apps externas obtienen public keys | `GET /.well-known/jwks.json` | 🟢 Baja |
| **UC-14: OAuth2 Authorization** | Flujo OAuth2 authorization code | `GET /oauth2/authorize` | 🟢 Baja |
| **UC-15: OAuth2 Token Exchange** | Exchange code por tokens | `POST /oauth2/token` | 🟢 Baja |

---

## Diagramas de Secuencia

### UC-01: Registro de Usuario

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth Service
    participant Validator
    participant UserService
    participant HashPkg as Argon2
    participant UserRepo
    participant DB as PostgreSQL

    Client->>API: POST /api/v1/auth/register
    Note over Client,API: {email, password, first_name, last_name}

    API->>Validator: Validate(request)
    Validator-->>API: ✓ Valid

    API->>UserService: Register(ctx, req)

    UserService->>UserRepo: GetByEmail(email)
    UserRepo->>DB: SELECT * FROM users WHERE email=?
    DB-->>UserRepo: NULL (user doesn't exist)
    UserRepo-->>UserService: nil

    UserService->>HashPkg: HashPassword(password)
    Note over HashPkg: Argon2id hashing<br/>64MB memory, 3 iterations
    HashPkg-->>UserService: passwordHash

    UserService->>UserRepo: Create(user)
    UserRepo->>DB: INSERT INTO users...
    DB-->>UserRepo: User ID
    UserRepo-->>UserService: user

    UserService-->>API: user
    API-->>Client: 201 Created
    Note over API,Client: {message, user: {id, email, ...}}
```

**Flujo:**
1. Cliente envía datos de registro
2. Se validan los campos (email válido, password ≥8 chars)
3. Se verifica que el email no exista
4. Se hashea la password con Argon2id
5. Se crea el usuario con status "active" pero email_verified=false
6. Se retorna el usuario creado

**⚠️ FALTANTE:**
- No se envía email de verificación
- El usuario puede hacer login sin verificar email

---

### UC-02: Login (Sin MFA)

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth Service
    participant AuthService
    participant UserRepo
    participant DB as PostgreSQL
    participant HashPkg as Argon2
    participant JWTService
    participant SessionRepo
    participant Redis

    Client->>API: POST /api/v1/auth/login
    Note over Client,API: {email, password, app_id}

    API->>AuthService: Login(ctx, req)

    AuthService->>UserRepo: GetByEmail(email)
    UserRepo->>DB: SELECT * FROM users WHERE email=?
    DB-->>UserRepo: user
    UserRepo-->>AuthService: user

    alt Account is locked
        AuthService-->>API: ErrAccountLocked
        API-->>Client: 403 Forbidden
    end

    AuthService->>HashPkg: VerifyPassword(password, user.PasswordHash)
    HashPkg-->>AuthService: valid=true

    alt Password is invalid
        AuthService->>UserRepo: IncrementFailedLogins(user.id)
        UserRepo->>DB: UPDATE users SET failed_logins=failed_logins+1
        alt failed_logins >= 5
            Note over AuthService: Lock account for 15 min
            AuthService->>UserRepo: Update(user) - set locked_until
        end
        AuthService-->>API: ErrInvalidCredentials
        API-->>Client: 401 Unauthorized
    end

    AuthService->>UserRepo: GetUserRoles(user.id, app_id)
    UserRepo->>DB: SELECT roles FROM user_roles<br/>JOIN roles ON...
    DB-->>UserRepo: ["admin", "user"]
    UserRepo-->>AuthService: roles

    AuthService->>JWTService: GenerateTokenPair(user, roles, app_id)
    Note over JWTService: Access: 15min<br/>Refresh: 7 days<br/>RS256 signing
    JWTService-->>AuthService: {access_token, refresh_token}

    AuthService->>SessionRepo: Create(session)
    Note over AuthService,SessionRepo: Hash refresh token with SHA-256
    SessionRepo->>DB: INSERT INTO sessions<br/>(user_id, refresh_token_hash, ...)
    DB-->>SessionRepo: session_id

    AuthService->>UserRepo: ResetFailedLogins(user.id)
    AuthService->>UserRepo: UpdateLastLogin(user.id)

    AuthService-->>API: LoginResponse{tokens, user}
    API-->>Client: 200 OK
    Note over API,Client: {tokens: {access_token, refresh_token,<br/>expires_at, token_type},<br/>user: {id, email, ...}}
```

**Flujo:**
1. Cliente envía credenciales + app_id
2. Se busca el usuario por email
3. Se verifica si la cuenta está bloqueada
4. Se verifica la password con Argon2
5. Si falla, se incrementa contador de intentos fallidos
6. Si falla 5 veces, se bloquea la cuenta por 15 minutos
7. Se obtienen los roles del usuario para esa app específica
8. Se genera par de tokens JWT (access + refresh)
9. Se crea sesión en DB hasheando el refresh token
10. Se resetea contador de intentos fallidos
11. Se actualiza last_login timestamp

**⚠️ CONSIDERACIONES:**
- El bloqueo de cuenta es temporal (15 min)
- Cada app puede tener roles diferentes para el mismo usuario
- El refresh token se almacena hasheado en DB

---

### UC-02b: Login (Con MFA) - ⏳ PENDIENTE

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant MFAService
    participant Redis

    Client->>API: POST /api/v1/auth/login
    Note over Client,API: {email, password, app_id}

    API->>AuthService: Login(ctx, req)

    Note over AuthService: Steps 1-4 same as UC-02

    alt User has MFA enabled
        alt MFA code not provided
            AuthService->>Redis: Store temp token (5 min TTL)
            Note over AuthService,Redis: user_id + session context
            AuthService-->>API: MFARequired{mfa_token}
            API-->>Client: 200 OK - MFA Required
            Note over Client: User needs to provide MFA code

            Client->>API: POST /api/v1/auth/mfa/verify
            Note over Client,API: {mfa_token, mfa_code}

            API->>MFAService: VerifyCode(user.mfa_secret, code)
            MFAService-->>API: valid=true

            Note over AuthService: Continue with token generation
        else MFA code provided
            AuthService->>MFAService: VerifyCode(user.mfa_secret, req.mfa_code)
            alt Invalid MFA code
                AuthService-->>API: ErrInvalidMFACode
                API-->>Client: 401 Unauthorized
            end
        end
    end

    Note over AuthService: Continue UC-02 flow (steps 5-11)
```

**⚠️ FALTANTE:** Este flujo NO está implementado actualmente

---

### UC-03: Refresh Token

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant JWTService
    participant SessionRepo
    participant DB
    participant UserRepo

    Client->>API: POST /api/v1/auth/refresh
    Note over Client,API: {refresh_token}

    API->>AuthService: RefreshToken(ctx, refresh_token)

    AuthService->>JWTService: ValidateToken(refresh_token)
    JWTService-->>AuthService: claims

    alt Token type != "refresh"
        AuthService-->>API: Error: invalid token type
        API-->>Client: 401 Unauthorized
    end

    AuthService->>AuthService: hashToken(refresh_token)
    Note over AuthService: SHA-256 hash

    AuthService->>SessionRepo: GetByToken(tokenHash)
    SessionRepo->>DB: SELECT * FROM sessions<br/>WHERE refresh_token_hash=?<br/>AND expires_at > NOW()

    alt Session not found or expired
        DB-->>SessionRepo: NULL
        SessionRepo-->>AuthService: Error
        AuthService-->>API: Error: session not found
        API-->>Client: 401 Unauthorized
    end

    DB-->>SessionRepo: session
    SessionRepo-->>AuthService: session

    AuthService->>UserRepo: GetByID(claims.user_id)
    UserRepo->>DB: SELECT * FROM users WHERE id=?
    DB-->>UserRepo: user
    UserRepo-->>AuthService: user

    AuthService->>UserRepo: GetUserRoles(user.id, claims.app_id)
    UserRepo-->>AuthService: roles

    AuthService->>JWTService: GenerateTokenPair(user, roles, app_id)
    Note over JWTService: New access + refresh tokens<br/>Token Rotation for security
    JWTService-->>AuthService: new_tokens

    AuthService->>AuthService: hashToken(new_tokens.refresh_token)

    AuthService->>SessionRepo: Update(session)
    Note over AuthService,SessionRepo: Update session with NEW refresh token hash<br/>and new expiry
    SessionRepo->>DB: UPDATE sessions SET<br/>refresh_token_hash=?,<br/>expires_at=?
    DB-->>SessionRepo: ✓

    AuthService-->>API: new_tokens
    API-->>Client: 200 OK
    Note over API,Client: {access_token, refresh_token,<br/>expires_at, token_type}
```

**Flujo:**
1. Cliente envía refresh token actual
2. Se valida el JWT y se verifica que sea tipo "refresh"
3. Se hashea el token con SHA-256
4. Se busca la sesión en DB por el hash
5. Se verifica que no esté expirada
6. Se obtiene el usuario y sus roles
7. Se genera un NUEVO par de tokens (rotation)
8. Se actualiza la sesión con el NUEVO refresh token hasheado
9. El viejo refresh token queda invalidado

**🔒 SEGURIDAD:**
- **Refresh Token Rotation**: Cada refresh invalida el token anterior
- Protege contra ataques de replay
- Si se detecta uso de token viejo, podría ser robo → invalidar todas las sesiones

---

### UC-04: Logout

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthService
    participant SessionRepo
    participant DB

    Client->>API: POST /api/v1/auth/logout
    Note over Client,API: {refresh_token}

    API->>AuthService: Logout(ctx, refresh_token)

    AuthService->>AuthService: hashToken(refresh_token)
    Note over AuthService: SHA-256 hash

    AuthService->>SessionRepo: DeleteByToken(tokenHash)
    SessionRepo->>DB: DELETE FROM sessions<br/>WHERE refresh_token_hash=?
    DB-->>SessionRepo: rows_affected=1
    SessionRepo-->>AuthService: ✓

    AuthService-->>API: nil (success)
    API-->>Client: 200 OK
    Note over API,Client: {message: "Logged out successfully"}
```

**Flujo:**
1. Cliente envía su refresh token
2. Se hashea el token
3. Se elimina la sesión de DB
4. El refresh token queda invalidado
5. El access token sigue siendo válido hasta su expiración

**⚠️ LIMITACIÓN ACTUAL:**
- El access token sigue funcionando hasta que expire (max 15 min)
- Para invalidación inmediata, se necesitaría:
  - Redis blacklist de access tokens
  - O validar cada request contra DB (más lento)

---

### UC-05: Obtener Perfil (Ruta Protegida)

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AuthMiddleware
    participant JWTService
    participant UserHandler
    participant UserService
    participant UserRepo
    participant DB

    Client->>API: GET /api/v1/users/me
    Note over Client,API: Header: Authorization: Bearer <access_token>

    API->>AuthMiddleware: AuthMiddleware(ctx)

    AuthMiddleware->>AuthMiddleware: Extract Bearer token

    alt No Authorization header
        AuthMiddleware-->>API: 401 Unauthorized
        API-->>Client: {error: "missing authorization header"}
    end

    alt Invalid format (not "Bearer <token>")
        AuthMiddleware-->>API: 401 Unauthorized
        API-->>Client: {error: "invalid authorization format"}
    end

    AuthMiddleware->>JWTService: ValidateToken(token)

    alt Token expired or invalid
        JWTService-->>AuthMiddleware: Error
        AuthMiddleware-->>API: 401 Unauthorized
        API-->>Client: {error: "invalid token"}
    end

    JWTService-->>AuthMiddleware: claims

    alt claims.TokenType != "access"
        AuthMiddleware-->>API: 401 Unauthorized
        API-->>Client: {error: "invalid token type"}
    end

    AuthMiddleware->>AuthMiddleware: Store in fiber.Locals()
    Note over AuthMiddleware: c.Locals("user_id", claims.UserID)<br/>c.Locals("email", claims.Email)<br/>c.Locals("roles", claims.Roles)<br/>c.Locals("claims", claims)

    AuthMiddleware->>UserHandler: c.Next() → GetMe(ctx)

    UserHandler->>UserHandler: Extract user_id from Locals

    UserHandler->>UserService: GetByID(ctx, user_id)
    UserService->>UserRepo: GetByID(user_id)
    UserRepo->>DB: SELECT * FROM users WHERE id=?
    DB-->>UserRepo: user
    UserRepo-->>UserService: user
    UserService-->>UserHandler: user

    UserHandler-->>Client: 200 OK
    Note over UserHandler,Client: {id, email, first_name, last_name,<br/>status, email_verified, mfa_enabled,<br/>created_at, updated_at, last_login_at}
```

**Flujo:**
1. Cliente envía request con access token en header
2. AuthMiddleware intercepta el request
3. Extrae y valida el token JWT
4. Verifica que sea tipo "access" (no "refresh")
5. Almacena claims en fiber.Locals para handlers
6. Handler extrae user_id de Locals
7. Obtiene datos del usuario de DB
8. Retorna información del perfil

**🔒 SEGURIDAD:**
- Middleware valida CADA request a rutas protegidas
- No se consulta DB para validar token (solo firma criptográfica)
- Rápido pero access token sigue válido hasta expirar

---

### UC-07: Verificación de Email - ⏳ PENDIENTE

```mermaid
sequenceDiagram
    participant Client
    participant EmailService
    participant API
    participant UserService
    participant TokenRepo
    participant DB
    participant UserRepo

    Note over Client,EmailService: After registration (UC-01)

    UserService->>TokenRepo: CreateVerificationToken(user_id)
    TokenRepo->>DB: INSERT INTO email_verifications<br/>(user_id, token, expires_at)
    Note over DB: Token válido por 24h
    DB-->>TokenRepo: token

    UserService->>EmailService: SendVerificationEmail(user.email, token)
    Note over EmailService: Email con link:<br/>http://app.com/verify-email?token=...
    EmailService-->>Client: 📧 Email sent

    Client->>API: Click link → GET /api/v1/auth/verify-email/:token

    API->>UserService: VerifyEmail(token)
    UserService->>TokenRepo: GetByToken(token)
    TokenRepo->>DB: SELECT * FROM email_verifications<br/>WHERE token=? AND verified=false

    alt Token not found or expired
        DB-->>TokenRepo: NULL
        TokenRepo-->>UserService: Error
        UserService-->>API: Error: invalid or expired token
        API-->>Client: 400 Bad Request
    end

    DB-->>TokenRepo: verification
    TokenRepo-->>UserService: verification

    UserService->>UserRepo: Update(user_id, email_verified=true)
    UserRepo->>DB: UPDATE users SET email_verified=true

    UserService->>TokenRepo: MarkAsVerified(token)
    TokenRepo->>DB: UPDATE email_verifications<br/>SET verified=true

    UserService-->>API: Success
    API-->>Client: 200 OK / Redirect to app
```

**✅ IMPLEMENTADO** - La funcionalidad usa campos `email_verification_token` y `email_verification_token_expires_at` en la tabla `users` directamente. La tabla `email_verifications` fue removida en v1.5.0 (no se usaba).

---

### UC-08 & UC-09: Reset Password - ⏳ PENDIENTE

```mermaid
sequenceDiagram
    participant Client
    participant EmailService
    participant API
    participant AuthService
    participant TokenRepo
    participant DB
    participant UserRepo
    participant HashPkg

    Client->>API: POST /api/v1/auth/forgot-password
    Note over Client,API: {email}

    API->>AuthService: RequestPasswordReset(email)
    AuthService->>UserRepo: GetByEmail(email)

    alt User not found
        Note over AuthService: Return success anyway<br/>(security: don't leak email existence)
        AuthService-->>API: Success
        API-->>Client: 200 OK
    end

    UserRepo-->>AuthService: user

    AuthService->>TokenRepo: CreateResetToken(user_id)
    TokenRepo->>DB: INSERT INTO password_resets<br/>(user_id, token, expires_at)
    Note over DB: Token válido por 1h
    DB-->>TokenRepo: token

    AuthService->>EmailService: SendResetEmail(user.email, token)
    Note over EmailService: Email con link:<br/>http://app.com/reset-password?token=...
    EmailService-->>Client: 📧 Email sent

    AuthService-->>API: Success
    API-->>Client: 200 OK
    Note over API,Client: {message: "If email exists,<br/>reset link sent"}

    rect rgb(200, 220, 240)
        Note over Client,API: User clicks link in email

        Client->>API: POST /api/v1/auth/reset-password
        Note over Client,API: {token, new_password}

        API->>AuthService: ResetPassword(token, new_password)
        AuthService->>TokenRepo: GetByToken(token)
        TokenRepo->>DB: SELECT * FROM password_resets<br/>WHERE token=? AND used=false

        alt Token not found, expired, or used
            DB-->>TokenRepo: NULL
            TokenRepo-->>AuthService: Error
            AuthService-->>API: Error: invalid token
            API-->>Client: 400 Bad Request
        end

        DB-->>TokenRepo: reset_token
        TokenRepo-->>AuthService: reset_token

        AuthService->>HashPkg: HashPassword(new_password)
        HashPkg-->>AuthService: password_hash

        AuthService->>UserRepo: Update(user_id, password_hash)
        UserRepo->>DB: UPDATE users SET password_hash=?

        AuthService->>TokenRepo: MarkAsUsed(token)
        TokenRepo->>DB: UPDATE password_resets SET used=true

        AuthService-->>API: Success
        API-->>Client: 200 OK
    end
```

**✅ IMPLEMENTADO** - La funcionalidad usa campos `password_reset_token` y `password_reset_token_expires_at` en la tabla `users` directamente. La tabla `password_resets` fue removida en v1.5.0 (no se usaba).

---

## Funcionalidades Implementadas vs Pendientes

### ✅ Completamente Implementadas

| Feature | Status | Notas |
|---------|--------|-------|
| User Registration | ✅ | Con validación de email único |
| Login con Password | ✅ | Argon2id verification |
| JWT Token Generation | ✅ | RS256 con access + refresh |
| Refresh Token Rotation | ✅ | Seguro con SHA-256 hashing |
| Logout | ✅ | Invalida refresh token |
| Account Locking | ✅ | 5 intentos fallidos → 15 min lock |
| Session Management | ✅ | PostgreSQL + Redis ready |
| Protected Routes | ✅ | Middleware con JWT validation |
| User Profile | ✅ | GET /users/me |
| Health Checks | ✅ | /health y /ready |
| Multi-App Support | ✅ | Roles por app_id |
| RBAC Foundation | ✅ | Tablas de roles/permisos |

### ⏳ Parcialmente Implementadas

| Feature | Status | Qué Falta |
|---------|--------|-----------|
| Email Verification | 🟡 | Tabla existe, falta servicio/handler/email sender |
| Password Reset | 🟡 | Tabla existe, falta servicio/handler/email sender |
| MFA/2FA | 🟡 | Campos en user table, falta servicio completo |
| Role Management | 🟡 | Modelo existe, falta CRUD endpoints |

### ❌ No Implementadas

| Feature | Priority | Effort | Notas |
|---------|----------|--------|-------|
| Email Service Integration | 🔴 Alta | Medium | SendGrid, AWS SES, etc. |
| MFA Setup/Verify | 🟡 Media | Medium | TOTP con google/pquerna/otp |
| JWKS Endpoint | 🟢 Baja | Small | Para validación externa de JWTs |
| OAuth2 Provider | 🟢 Baja | Large | Autorización para third-party apps |
| Social Login | 🟢 Baja | Medium | Google, GitHub, etc. |
| Audit Logging | 🟡 Media | Small | Tabla existe, falta integración |
| Rate Limiting | 🟡 Media | Small | Por IP/usuario en endpoints críticos |
| Session Management UI | 🟢 Baja | Medium | Listar/revocar sesiones activas |

---

## Modelo de Datos

### Diagrama ER

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : has
    USERS ||--o{ USER_ROLES : has
    USERS ||--o{ EMAIL_VERIFICATIONS : has
    USERS ||--o{ PASSWORD_RESETS : has
    USERS ||--o{ AUDIT_LOGS : generates

    APPS ||--o{ ROLES : defines
    ROLES ||--o{ USER_ROLES : assigned_to
    ROLES ||--o{ ROLE_PERMISSIONS : has
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : belongs_to

    USERS {
        uuid id PK
        string email UK
        string password_hash
        string first_name
        string last_name
        enum status
        bool email_verified
        bool mfa_enabled
        string mfa_secret
        int failed_logins
        timestamp locked_until
        timestamp created_at
        timestamp updated_at
        timestamp last_login_at
    }

    SESSIONS {
        uuid id PK
        uuid user_id FK
        string refresh_token_hash UK
        string user_agent
        inet ip_address
        timestamp expires_at
        timestamp created_at
    }

    APPS {
        uuid id PK
        string name
        string client_id UK
        string client_secret_hash
        array redirect_uris
        array allowed_scopes
    }

    ROLES {
        uuid id PK
        uuid app_id FK
        string name
        string description
    }

    PERMISSIONS {
        uuid id PK
        string name
        string resource
        string action
    }
```

### Estados de Usuario

```mermaid
stateDiagram-v2
    [*] --> Active: Register

    Active --> Locked: 5 failed logins
    Locked --> Active: Auto unlock after 15min
    Locked --> Active: Admin unlock

    Active --> Inactive: Admin deactivate
    Inactive --> Active: Admin activate

    Active --> [*]: Delete account

    note right of Active
        email_verified: false → true
        (via email verification)
    end note

    note right of Locked
        locked_until: timestamp
        failed_logins: ≥5
    end note
```

---

## Seguridad

### Layers de Seguridad

```mermaid
graph TB
    subgraph "Layer 1: Network"
        A[HTTPS/TLS]
        B[Rate Limiting]
        C[CORS]
    end

    subgraph "Layer 2: Authentication"
        D[Password Hashing<br/>Argon2id]
        E[JWT RS256<br/>Asymmetric]
        F[Refresh Token<br/>SHA-256]
    end

    subgraph "Layer 3: Authorization"
        G[Role-Based Access<br/>RBAC]
        H[Permission System]
        I[Multi-App Isolation]
    end

    subgraph "Layer 4: Session Security"
        J[Account Locking]
        K[Token Rotation]
        L[Session Expiry]
    end

    subgraph "Layer 5: Audit & Monitoring"
        M[Audit Logs]
        N[Failed Login Tracking]
        O[Health Monitoring]
    end

    A --> D
    B --> D
    C --> E
    D --> G
    E --> G
    F --> J
    G --> M
    H --> M
    I --> M
    J --> N
    K --> N
    L --> O
```

### Token Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant AuthService
    participant Database
    participant Redis

    Note over User,Redis: Login Flow
    User->>AuthService: Login (email, password)
    AuthService->>Database: Verify user & get roles
    AuthService->>AuthService: Generate Access Token (15 min)
    AuthService->>AuthService: Generate Refresh Token (7 days)
    AuthService->>Database: Store hashed refresh token
    AuthService-->>User: Return both tokens

    Note over User,Redis: Normal API Usage
    User->>AuthService: API Request + Access Token
    AuthService->>AuthService: Validate JWT (crypto only)
    AuthService-->>User: Response

    Note over User,Redis: Token Refresh (before 15min expires)
    User->>AuthService: Refresh Request + Refresh Token
    AuthService->>Database: Verify refresh token hash
    AuthService->>AuthService: Generate NEW tokens
    AuthService->>Database: Update session with new hash
    AuthService-->>User: Return new tokens
    Note over AuthService,Database: Old refresh token invalidated

    Note over User,Redis: Logout
    User->>AuthService: Logout + Refresh Token
    AuthService->>Database: Delete session
    Note over User: Access token still valid until expires
```

---

## Próximos Pasos Recomendados

### Fase 1: Completar Funcionalidades Core (1-2 semanas)

1. **Email Service Integration** 🔴
   - Integrar SendGrid o AWS SES
   - Implementar handlers para verify-email
   - Implementar forgot-password/reset-password
   - Templates de emails

2. **MFA/2FA Setup** 🟡
   - Implementar /mfa/setup (genera QR con TOTP secret)
   - Implementar /mfa/verify
   - Modificar login flow para soportar MFA
   - Implementar /mfa/disable

3. **Rate Limiting** 🟡
   - Middleware de rate limiting por IP
   - Límites especiales para /login (más restrictivo)
   - Redis para contador distribuido

### Fase 2: Seguridad y Observabilidad (1 semana)

4. **Audit Logging** 🟡
   - Loggear eventos críticos (login, logout, password change, etc.)
   - Integrar con audit_logs table
   - Endpoint para consultar logs propios

5. **Session Management** 🟢
   - GET /sessions - Listar sesiones activas
   - DELETE /sessions/:id - Revocar sesión específica
   - DELETE /sessions/all - Cerrar todas las sesiones

### Fase 3: Advanced Features (2-3 semanas)

6. **JWKS Endpoint** 🟢
   - GET /.well-known/jwks.json
   - Para que otras apps validen tokens sin shared secret

7. **OAuth2 Provider** 🟢
   - Authorization Code Flow
   - PKCE support
   - Consent screen

8. **Social Login** 🟢
   - OAuth2 clients para Google, GitHub
   - Link/unlink social accounts

---

## Conclusión

### ✅ Lo que tenemos es SÓLIDO:
- Arquitectura limpia y escalable
- Seguridad robusta (Argon2, RS256, token rotation)
- Multi-tenancy ready
- RBAC foundation

### ⚠️ Lo que FALTA para producción:
1. **Email verification** (crítico para seguridad)
2. **Password reset** (crítico para UX)
3. **MFA** (recomendado para apps sensibles)
4. **Rate limiting** (protección contra ataques)
5. **Audit logging** (compliance/debugging)

### 🎯 Prioridad de Implementación:
1. 🔴 **Email service + verification + reset** (1 semana)
2. 🟡 **Rate limiting** (2 días)
3. 🟡 **MFA/2FA** (3-4 días)
4. 🟡 **Session management endpoints** (2 días)
5. 🟢 **JWKS + OAuth2** (optional, 1-2 semanas)

**El sistema actual es funcional y seguro para desarrollo/staging, pero necesita las funcionalidades marcadas con 🔴 y 🟡 para producción.**
