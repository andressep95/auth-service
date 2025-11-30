# Diagramas de Secuencia

Este documento contiene los diagramas de secuencia de los flujos principales del Auth Service.

## 📋 Índice

1. [Login Flow](#login-flow)
2. [Token Refresh Flow](#token-refresh-flow)
3. [Password Reset Flow](#password-reset-flow)
4. [Email Verification Flow](#email-verification-flow)
5. [RBAC Authorization Flow](#rbac-authorization-flow)

---

## Login Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Auth API
    participant DB as PostgreSQL
    participant Redis as Redis
    participant JWT as JWT Service

    C->>API: POST /auth/login
    API->>DB: GetUserByEmail(email)
    DB-->>API: User
    
    alt Account Locked
        API-->>C: 423 Account Locked
    end
    
    API->>API: VerifyPassword(password, hash)
    
    alt Invalid Password
        API->>DB: IncrementFailedLogins()
        API-->>C: 401 Invalid Credentials
    end
    
    API->>DB: ResetFailedLogins()
    API->>DB: GetUserRoles(userID, appID)
    DB-->>API: Roles[]
    
    API->>JWT: GenerateTokenPair(user, roles)
    JWT-->>API: TokenPair
    
    API->>DB: CreateSession(refreshToken)
    API->>DB: UpdateLastLogin(userID)
    
    API-->>C: 200 OK + Tokens
```

---

## Token Refresh Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Auth API
    participant DB as PostgreSQL
    participant Redis as Redis
    participant JWT as JWT Service

    C->>API: POST /auth/refresh
    API->>JWT: ValidateToken(refreshToken)
    
    alt Invalid Token
        API-->>C: 401 Unauthorized
    end
    
    API->>DB: GetSessionByToken(hash)
    
    alt Session Not Found
        API-->>C: 401 Session Not Found
    end
    
    API->>DB: GetUserByID(userID)
    API->>DB: GetUserRoles(userID, appID)
    
    API->>JWT: GenerateTokenPair(user, roles)
    JWT-->>API: NewTokenPair
    
    API->>DB: UpdateSession(newRefreshToken)
    
    API-->>C: 200 OK + New Tokens
```

---

## Password Reset Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client
    participant API as Auth API
    participant DB as PostgreSQL
    participant Redis as Redis
    participant Email as Email Service

    Note over U,Email: Step 1: Request Reset
    U->>C: Click "Forgot Password"
    C->>API: POST /auth/forgot-password
    API->>DB: GetUserByEmail(email)
    
    alt User Not Found
        API-->>C: 200 OK (security: don't reveal)
    end
    
    API->>API: GenerateResetToken()
    API->>DB: SaveResetToken(token, expires: 1h)
    API->>Email: SendPasswordResetEmail(token)
    API-->>C: 200 OK
    
    Note over U,Email: Step 2: Reset Password
    U->>U: Check Email
    U->>C: Click Reset Link
    C->>API: POST /auth/reset-password
    API->>DB: GetUserByResetToken(token)
    
    alt Token Invalid/Expired
        API-->>C: 400 Invalid Token
    end
    
    API->>API: HashPassword(newPassword)
    API->>DB: UpdatePassword(hash)
    API->>DB: ClearResetToken()
    
    Note over API,Redis: Invalidate All Sessions
    API->>DB: DeleteAllUserSessions(userID)
    API->>Redis: BlacklistUser(userID, NOW())
    
    API->>Email: SendPasswordChangedEmail()
    API-->>C: 200 OK
    
    Note over U: User must login with new password
```

---

## Email Verification Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client
    participant API as Auth API
    participant DB as PostgreSQL
    participant Email as Email Service

    Note over U,Email: Step 1: Registration
    U->>C: Fill Registration Form
    C->>API: POST /auth/register
    API->>API: HashPassword()
    API->>API: GenerateVerificationToken()
    API->>DB: CreateUser(emailVerified: false)
    API->>Email: SendVerificationEmail(token)
    API-->>C: 201 Created
    
    Note over U,Email: Step 2: Verification
    U->>U: Check Email
    U->>C: Click Verification Link
    C->>API: GET /auth/verify-email/:token
    API->>DB: GetUserByVerificationToken(token)
    
    alt Token Invalid/Expired
        API-->>C: 400 Invalid Token
    end
    
    API->>DB: UpdateUser(emailVerified: true)
    API->>DB: ClearVerificationToken()
    API->>Email: SendWelcomeEmail()
    API-->>C: 200 OK
```

---

## RBAC Authorization Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant MW as Auth Middleware
    participant BL as Blacklist Service
    participant JWT as JWT Service
    participant RBAC as RBAC Middleware
    participant H as Handler

    C->>MW: Request + Bearer Token
    MW->>JWT: ValidateToken(token)
    
    alt Invalid Token
        MW-->>C: 401 Unauthorized
    end
    
    MW->>BL: IsTokenBlacklisted(token)
    
    alt Token Blacklisted
        MW-->>C: 401 Token Revoked
    end
    
    MW->>BL: IsUserBlacklisted(userID, issuedAt)
    
    alt User Blacklisted
        MW-->>C: 401 Password Changed
    end
    
    MW->>MW: Extract Claims (userID, roles)
    MW->>RBAC: CheckPermissions(roles, required)
    
    alt Insufficient Permissions
        RBAC-->>C: 403 Forbidden
    end
    
    RBAC->>H: Forward Request
    H-->>C: 200 OK + Response
```

---

## Token Blacklist Validation

```mermaid
sequenceDiagram
    participant MW as Middleware
    participant Redis as Redis
    participant JWT as JWT Claims

    Note over MW,JWT: Validación en cada request
    
    MW->>Redis: GET blacklist:token:{hash}
    
    alt Token específico en blacklist
        Redis-->>MW: EXISTS
        MW-->>MW: REJECT (401)
    end
    
    MW->>Redis: GET blacklist:user:{userID}
    
    alt User no está en blacklist
        Redis-->>MW: NIL
        MW-->>MW: ACCEPT ✅
    end
    
    Redis-->>MW: invalidationTimestamp
    MW->>JWT: Get IssuedAt from token
    
    alt token.IssuedAt < invalidationTimestamp
        MW-->>MW: REJECT (401) ❌
    else token.IssuedAt >= invalidationTimestamp
        MW-->>MW: ACCEPT ✅
    end
```

---

## Change Password Flow (Authenticated User)

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Auth API
    participant DB as PostgreSQL
    participant Redis as Redis

    C->>API: PUT /users/me/password + Bearer Token
    API->>API: Extract userID from token
    API->>DB: GetUserByID(userID)
    API->>API: VerifyPassword(oldPassword)
    
    alt Invalid Old Password
        API-->>C: 401 Invalid Credentials
    end
    
    API->>API: HashPassword(newPassword)
    API->>DB: UpdatePassword(hash)
    
    Note over API,Redis: Invalidate All Sessions
    API->>DB: GetAllUserSessions(userID)
    API->>DB: DeleteAllSessions()
    API->>Redis: BlacklistUser(userID, NOW(), TTL: 24h)
    
    API-->>C: 200 OK
    
    Note over C: Current token now invalid
    Note over C: Must login with new password
```

---

## Notas de Implementación

### Token Blacklist por Timestamp

El sistema usa un enfoque inteligente para invalidar tokens:

1. **Al cambiar/resetear contraseña:**
   - Se guarda `timestamp_actual` en Redis
   - TTL de 24h (más largo que lifetime máximo de tokens)

2. **Al validar token:**
   - Se compara `token.IssuedAt` con `invalidation_timestamp`
   - Si `token.IssuedAt < invalidation_timestamp` → RECHAZAR
   - Si `token.IssuedAt >= invalidation_timestamp` → ACEPTAR

3. **Ventajas:**
   - ✅ Tokens antiguos se invalidan
   - ✅ Tokens nuevos funcionan inmediatamente
   - ✅ No hay bloqueo permanente del usuario
   - ✅ Limpieza automática después de 24h

### Seguridad en Password Reset

1. **Token de un solo uso:** Se elimina después de usarse
2. **Expiración corta:** 1 hora
3. **No revelar existencia:** Siempre retorna 200 OK
4. **Invalidación total:** Cierra todas las sesiones
5. **Confirmación por email:** Notifica al usuario

---

## Herramientas para Visualización

Estos diagramas están en formato Mermaid y pueden visualizarse en:

- GitHub (renderiza automáticamente)
- VS Code (con extensión Mermaid)
- [Mermaid Live Editor](https://mermaid.live/)
- Notion, Confluence, GitLab, etc.

---

**Última actualización:** 2024-11-30  
**Versión:** 1.1.0
