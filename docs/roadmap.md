# Roadmap de Implementación - Auth Service

## 📊 Estado Actual vs Objetivo

### Funcionalidades por Categoría

| Categoría | Implementadas | Pendientes | % Completado |
|-----------|---------------|------------|--------------|
| **Autenticación Básica** | 4/4 | 0/4 | 100% ✅ |
| **Gestión de Sesiones** | 3/3 | 0/3 | 100% ✅ |
| **Recuperación de Cuenta** | 0/2 | 2/2 | 0% ❌ |
| **Seguridad Avanzada** | 1/3 | 2/3 | 33% 🟡 |
| **Multi-Factor Auth** | 0/3 | 3/3 | 0% ❌ |
| **Gestión de Usuarios** | 1/4 | 3/4 | 25% 🟡 |
| **OAuth2/OIDC** | 0/5 | 5/5 | 0% ❌ |
| **Observabilidad** | 1/3 | 2/3 | 33% 🟡 |

**Total: 10/27 funcionalidades (37% completo)**

---

## 🎯 Plan de Implementación

## FASE 1: Funcionalidades Críticas (Semana 1-2) 🔴

### 1.1 Email Service Integration

**Problema actual:** Los usuarios se registran pero no verifican su email.

**Solución:**

```go
// pkg/email/sender.go
package email

import (
    "fmt"
    "github.com/sendgrid/sendgrid-go"
    "github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailService struct {
    apiKey     string
    fromEmail  string
    fromName   string
    baseURL    string // Para links en emails
}

func NewEmailService(apiKey, fromEmail, fromName, baseURL string) *EmailService {
    return &EmailService{
        apiKey:    apiKey,
        fromEmail: fromEmail,
        fromName:  fromName,
        baseURL:   baseURL,
    }
}

func (s *EmailService) SendVerificationEmail(to, token string) error {
    from := mail.NewEmail(s.fromName, s.fromEmail)
    subject := "Verifica tu cuenta"
    toEmail := mail.NewEmail("", to)

    verifyURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

    plainTextContent := fmt.Sprintf("Verifica tu cuenta: %s", verifyURL)
    htmlContent := fmt.Sprintf(`
        <h1>Bienvenido!</h1>
        <p>Haz clic en el siguiente link para verificar tu cuenta:</p>
        <a href="%s">Verificar Email</a>
        <p>Este link expira en 24 horas.</p>
    `, verifyURL)

    message := mail.NewSingleEmail(from, subject, toEmail, plainTextContent, htmlContent)
    client := sendgrid.NewSendClient(s.apiKey)

    _, err := client.Send(message)
    return err
}

func (s *EmailService) SendPasswordResetEmail(to, token string) error {
    // Similar implementation
}
```

**Handler:**

```go
// internal/handler/auth_handler.go - Agregar

func (h *AuthHandler) VerifyEmail(c *fiber.Ctx) error {
    token := c.Params("token")

    err := h.authService.VerifyEmail(c.Context(), token)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid or expired verification token",
        })
    }

    return c.JSON(fiber.Map{
        "message": "Email verified successfully",
    })
}
```

**Service:**

```go
// internal/service/email_service.go - Nuevo archivo

type EmailVerificationService struct {
    userRepo    repository.UserRepository
    tokenRepo   repository.TokenRepository
    emailSender *email.EmailService
}

func (s *EmailVerificationService) SendVerification(ctx context.Context, userID uuid.UUID) error {
    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        return err
    }

    // Generar token aleatorio seguro
    token := generateSecureToken(32)

    // Guardar en DB con expiración de 24h
    err = s.tokenRepo.CreateVerificationToken(ctx, userID, token, 24*time.Hour)
    if err != nil {
        return err
    }

    // Enviar email
    return s.emailSender.SendVerificationEmail(user.Email, token)
}

func (s *EmailVerificationService) VerifyEmail(ctx context.Context, token string) error {
    verification, err := s.tokenRepo.GetVerificationByToken(ctx, token)
    if err != nil {
        return ErrInvalidToken
    }

    if verification.ExpiresAt.Before(time.Now()) {
        return ErrTokenExpired
    }

    if verification.Verified {
        return ErrTokenAlreadyUsed
    }

    // Marcar email como verificado
    err = s.userRepo.UpdateEmailVerified(ctx, verification.UserID, true)
    if err != nil {
        return err
    }

    // Marcar token como usado
    return s.tokenRepo.MarkVerificationAsUsed(ctx, token)
}

func generateSecureToken(length int) string {
    b := make([]byte, length)
    rand.Read(b)
    return hex.EncodeToString(b)
}
```

**Repository:**

```go
// internal/repository/token_repository.go - Nuevo archivo

type TokenRepository interface {
    CreateVerificationToken(ctx context.Context, userID uuid.UUID, token string, ttl time.Duration) error
    GetVerificationByToken(ctx context.Context, token string) (*domain.EmailVerification, error)
    MarkVerificationAsUsed(ctx context.Context, token string) error

    CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, token string, ttl time.Duration) error
    GetPasswordResetByToken(ctx context.Context, token string) (*domain.PasswordReset, error)
    MarkPasswordResetAsUsed(ctx context.Context, token string) error
}
```

**Rutas:**

```go
// internal/handler/routes.go - Agregar
auth.Get("/verify-email/:token", authHandler.VerifyEmail)
auth.Post("/forgot-password", authHandler.ForgotPassword)
auth.Post("/reset-password", authHandler.ResetPassword)
```

**Configuración:**

```env
# .env
EMAIL_SERVICE=sendgrid  # o aws_ses, smtp
SENDGRID_API_KEY=your_api_key
EMAIL_FROM=noreply@yourapp.com
EMAIL_FROM_NAME=Your App
BASE_URL=https://yourapp.com
```

**Esfuerzo:** 2-3 días
**Prioridad:** 🔴 Crítica

---

### 1.2 Password Reset Flow

**Implementación:**

```go
// internal/service/auth_service.go - Agregar

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
    user, err := s.userRepo.GetByEmail(ctx, email)
    if err != nil {
        // No revelar si el email existe o no (security)
        return nil
    }

    token := generateSecureToken(32)

    err = s.tokenRepo.CreatePasswordResetToken(ctx, user.ID, token, 1*time.Hour)
    if err != nil {
        return err
    }

    return s.emailSender.SendPasswordResetEmail(user.Email, token)
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
    resetToken, err := s.tokenRepo.GetPasswordResetByToken(ctx, token)
    if err != nil {
        return ErrInvalidToken
    }

    if resetToken.ExpiresAt.Before(time.Now()) {
        return ErrTokenExpired
    }

    if resetToken.Used {
        return ErrTokenAlreadyUsed
    }

    // Hash new password
    passwordHash, err := hash.HashPassword(newPassword)
    if err != nil {
        return err
    }

    // Update user password
    err = s.userRepo.UpdatePassword(ctx, resetToken.UserID, passwordHash)
    if err != nil {
        return err
    }

    // Mark token as used
    err = s.tokenRepo.MarkPasswordResetAsUsed(ctx, token)
    if err != nil {
        return err
    }

    // SECURITY: Invalidate all existing sessions
    return s.sessionRepo.DeleteAllByUserID(ctx, resetToken.UserID)
}
```

**Esfuerzo:** 1-2 días
**Prioridad:** 🔴 Crítica

---

### 1.3 Rate Limiting

**Problema:** Sin rate limiting, el servicio es vulnerable a:
- Brute force attacks en /login
- Email bombing en /forgot-password
- DDoS

**Solución con Redis:**

```go
// pkg/ratelimit/limiter.go
package ratelimit

import (
    "context"
    "fmt"
    "time"
    "github.com/redis/go-redis/v9"
)

type Limiter struct {
    redis *redis.Client
}

type Config struct {
    Requests int           // Máximo de requests
    Window   time.Duration // Ventana de tiempo
}

func NewLimiter(redis *redis.Client) *Limiter {
    return &Limiter{redis: redis}
}

func (l *Limiter) Allow(ctx context.Context, key string, cfg Config) (bool, error) {
    redisKey := fmt.Sprintf("ratelimit:%s", key)

    count, err := l.redis.Incr(ctx, redisKey).Result()
    if err != nil {
        return false, err
    }

    if count == 1 {
        // Primera request, setear TTL
        l.redis.Expire(ctx, redisKey, cfg.Window)
    }

    return count <= int64(cfg.Requests), nil
}

func (l *Limiter) Reset(ctx context.Context, key string) error {
    return l.redis.Del(ctx, fmt.Sprintf("ratelimit:%s", key)).Err()
}
```

**Middleware:**

```go
// internal/handler/middleware/ratelimit.go
package middleware

import (
    "fmt"
    "github.com/gofiber/fiber/v2"
    "github.com/andressep95/auth-service/pkg/ratelimit"
)

func RateLimitMiddleware(limiter *ratelimit.Limiter, cfg ratelimit.Config) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Rate limit por IP
        ip := c.IP()
        key := fmt.Sprintf("ip:%s:%s", ip, c.Path())

        allowed, err := limiter.Allow(c.Context(), key, cfg)
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error": "Rate limit check failed",
            })
        }

        if !allowed {
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error": "Too many requests, please try again later",
            })
        }

        return c.Next()
    }
}
```

**Uso en rutas:**

```go
// internal/handler/routes.go
import "time"

// Rate limit más estricto para login
loginLimiter := middleware.RateLimitMiddleware(limiter, ratelimit.Config{
    Requests: 5,
    Window:   5 * time.Minute,
})

auth.Post("/login", loginLimiter, authHandler.Login)

// Rate limit para forgot-password
forgotPasswordLimiter := middleware.RateLimitMiddleware(limiter, ratelimit.Config{
    Requests: 3,
    Window:   15 * time.Minute,
})

auth.Post("/forgot-password", forgotPasswordLimiter, authHandler.ForgotPassword)

// Rate limit general para registro
registerLimiter := middleware.RateLimitMiddleware(limiter, ratelimit.Config{
    Requests: 10,
    Window:   1 * time.Hour,
})

auth.Post("/register", registerLimiter, userHandler.Register)
```

**Esfuerzo:** 1 día
**Prioridad:** 🔴 Crítica

---

## FASE 2: Seguridad Avanzada (Semana 3) 🟡

### 2.1 MFA/2FA Implementation

**Diagrama de Setup:**

```
User → /mfa/setup → Generate Secret → Show QR Code → User scans with Google Authenticator
     → /mfa/verify → Verify code → Enable MFA → Store secret
```

**Implementación:**

```go
// internal/service/mfa_service.go
package service

import (
    "github.com/pquerna/otp/totp"
    "image/png"
    "bytes"
)

type MFAService struct {
    userRepo repository.UserRepository
}

type MFASetupResponse struct {
    Secret  string `json:"secret"`
    QRCode  string `json:"qr_code"` // Base64 encoded PNG
    BackupCodes []string `json:"backup_codes"`
}

func (s *MFAService) SetupMFA(ctx context.Context, userID uuid.UUID) (*MFASetupResponse, error) {
    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        return nil, err
    }

    // Generate TOTP secret
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "YourApp",
        AccountName: user.Email,
    })
    if err != nil {
        return nil, err
    }

    // Generate QR code
    var buf bytes.Buffer
    img, err := key.Image(200, 200)
    if err != nil {
        return nil, err
    }
    png.Encode(&buf, img)
    qrCode := base64.StdEncoding.EncodeToString(buf.Bytes())

    // Generate backup codes
    backupCodes := s.generateBackupCodes(10)

    // Store secret (temporarily, until verified)
    err = s.userRepo.UpdateMFASecret(ctx, userID, key.Secret())
    if err != nil {
        return nil, err
    }

    return &MFASetupResponse{
        Secret:      key.Secret(),
        QRCode:      qrCode,
        BackupCodes: backupCodes,
    }, nil
}

func (s *MFAService) VerifyAndEnableMFA(ctx context.Context, userID uuid.UUID, code string) error {
    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        return err
    }

    if user.MFASecret == nil {
        return errors.New("MFA not set up")
    }

    // Verify TOTP code
    valid := totp.Validate(code, *user.MFASecret)
    if !valid {
        return errors.New("invalid MFA code")
    }

    // Enable MFA
    return s.userRepo.UpdateMFAEnabled(ctx, userID, true)
}

func (s *MFAService) VerifyCode(secret, code string) bool {
    return totp.Validate(code, secret)
}

func (s *MFAService) generateBackupCodes(count int) []string {
    codes := make([]string, count)
    for i := 0; i < count; i++ {
        codes[i] = generateSecureToken(8)
    }
    return codes
}
```

**Handler:**

```go
// internal/handler/mfa_handler.go
package handler

type MFAHandler struct {
    mfaService *service.MFAService
}

func (h *MFAHandler) SetupMFA(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(uuid.UUID)

    setup, err := h.mfaService.SetupMFA(c.Context(), userID)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    return c.JSON(setup)
}

func (h *MFAHandler) VerifyMFA(c *fiber.Ctx) error {
    var req struct {
        Code string `json:"code" validate:"required,len=6"`
    }

    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request",
        })
    }

    userID := c.Locals("user_id").(uuid.UUID)

    err := h.mfaService.VerifyAndEnableMFA(c.Context(), userID, req.Code)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    return c.JSON(fiber.Map{
        "message": "MFA enabled successfully",
    })
}

func (h *MFAHandler) DisableMFA(c *fiber.Ctx) error {
    var req struct {
        Code string `json:"code" validate:"required,len=6"`
    }

    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request",
        })
    }

    userID := c.Locals("user_id").(uuid.UUID)

    // Verify code before disabling
    user, _ := h.userService.GetByID(c.Context(), userID)
    if !h.mfaService.VerifyCode(*user.MFASecret, req.Code) {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid MFA code",
        })
    }

    // Disable MFA
    err := h.userRepo.UpdateMFAEnabled(c.Context(), userID, false)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    return c.JSON(fiber.Map{
        "message": "MFA disabled successfully",
    })
}
```

**Rutas:**

```go
// Protegidas con auth middleware
mfa := api.Group("/mfa", authMiddleware)
mfa.Post("/setup", mfaHandler.SetupMFA)
mfa.Post("/verify", mfaHandler.VerifyMFA)
mfa.Delete("/", mfaHandler.DisableMFA)
```

**Modificar Login para soportar MFA:**

```go
// internal/service/auth_service.go - Modificar Login

if user.MFAEnabled {
    if req.MFACode == "" {
        // Generate temporary MFA token
        mfaToken := generateSecureToken(32)

        // Store in Redis with 5 min TTL
        s.redis.Set(ctx, fmt.Sprintf("mfa:%s", mfaToken), user.ID.String(), 5*time.Minute)

        return &LoginResponse{
            MFARequired: true,
            MFAToken:    mfaToken,
        }, nil
    }

    // Verify MFA code
    if !s.mfaService.VerifyCode(*user.MFASecret, req.MFACode) {
        return nil, ErrInvalidMFACode
    }
}
```

**Esfuerzo:** 3-4 días
**Prioridad:** 🟡 Media-Alta

---

### 2.2 Audit Logging

**Implementación:**

```go
// internal/service/audit_service.go
package service

type AuditService struct {
    auditRepo repository.AuditRepository
}

type AuditEvent struct {
    UserID      *uuid.UUID
    EventType   string
    Description string
    IPAddress   string
    UserAgent   string
    Metadata    map[string]interface{}
}

func (s *AuditService) Log(ctx context.Context, event AuditEvent) error {
    return s.auditRepo.Create(ctx, &domain.AuditLog{
        UserID:      event.UserID,
        EventType:   event.EventType,
        Description: event.Description,
        IPAddress:   event.IPAddress,
        UserAgent:   event.UserAgent,
        Metadata:    event.Metadata,
        CreatedAt:   time.Now(),
    })
}
```

**Eventos a loggear:**

```go
const (
    EventUserRegistered      = "user.registered"
    EventUserLogin           = "user.login"
    EventUserLoginFailed     = "user.login_failed"
    EventUserLogout          = "user.logout"
    EventPasswordChanged     = "user.password_changed"
    EventPasswordResetRequest = "user.password_reset_requested"
    EventPasswordReset       = "user.password_reset"
    EventMFAEnabled          = "user.mfa_enabled"
    EventMFADisabled         = "user.mfa_disabled"
    EventAccountLocked       = "user.account_locked"
    EventSessionCreated      = "session.created"
    EventSessionRevoked      = "session.revoked"
)
```

**Uso:**

```go
// En cada handler importante
auditService.Log(ctx, AuditEvent{
    UserID:      &user.ID,
    EventType:   EventUserLogin,
    Description: "User logged in successfully",
    IPAddress:   c.IP(),
    UserAgent:   c.Get("User-Agent"),
    Metadata: map[string]interface{}{
        "app_id": req.AppID,
    },
})
```

**Endpoint para consultar logs:**

```go
// GET /api/v1/users/me/audit-logs
func (h *UserHandler) GetMyAuditLogs(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(uuid.UUID)

    logs, err := h.auditService.GetByUserID(c.Context(), userID, 50) // Últimos 50
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }

    return c.JSON(logs)
}
```

**Esfuerzo:** 2 días
**Prioridad:** 🟡 Media

---

## FASE 3: Gestión de Sesiones (Semana 4) 🟢

### 3.1 Session Management UI

**Endpoints:**

```go
// GET /api/v1/users/me/sessions - Listar sesiones activas
func (h *UserHandler) GetMySessions(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(uuid.UUID)

    sessions, err := h.sessionService.GetByUserID(c.Context(), userID)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }

    // Enriquecer con info del device/browser
    for i, session := range sessions {
        sessions[i].IsCurrent = session.ID == getCurrentSessionID(c)
        sessions[i].DeviceInfo = parseUserAgent(session.UserAgent)
    }

    return c.JSON(sessions)
}

// DELETE /api/v1/users/me/sessions/:id - Revocar sesión específica
func (h *UserHandler) RevokeSession(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(uuid.UUID)
    sessionID := c.Params("id")

    err := h.sessionService.RevokeSession(c.Context(), userID, sessionID)
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }

    return c.JSON(fiber.Map{"message": "Session revoked"})
}

// DELETE /api/v1/users/me/sessions/all - Cerrar todas las sesiones
func (h *UserHandler) RevokeAllSessions(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(uuid.UUID)
    currentSessionID := getCurrentSessionID(c)

    err := h.sessionService.RevokeAllExcept(c.Context(), userID, currentSessionID)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }

    return c.JSON(fiber.Map{"message": "All other sessions revoked"})
}
```

**Response Example:**

```json
{
  "sessions": [
    {
      "id": "uuid",
      "created_at": "2024-01-01T00:00:00Z",
      "expires_at": "2024-01-08T00:00:00Z",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "device_info": {
        "device": "Desktop",
        "os": "macOS",
        "browser": "Chrome"
      },
      "is_current": true
    }
  ]
}
```

**Esfuerzo:** 2 días
**Prioridad:** 🟢 Baja-Media

---

## FASE 4: OAuth2/OIDC Provider (Semana 5-6) 🟢

### 4.1 JWKS Endpoint

**Implementación simple:**

```go
// internal/handler/jwks_handler.go
package handler

import (
    "crypto/rsa"
    "encoding/base64"
    "math/big"
)

type JWKSHandler struct {
    publicKey *rsa.PublicKey
}

func (h *JWKSHandler) GetJWKS(c *fiber.Ctx) error {
    // Convert RSA public key to JWK format
    n := base64.RawURLEncoding.EncodeToString(h.publicKey.N.Bytes())
    e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.publicKey.E)).Bytes())

    jwks := map[string]interface{}{
        "keys": []map[string]interface{}{
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "auth-service-2024",
                "alg": "RS256",
                "n":   n,
                "e":   e,
            },
        },
    }

    return c.JSON(jwks)
}
```

**Ruta:**

```go
app.Get("/.well-known/jwks.json", jwksHandler.GetJWKS)
```

**Uso:** Otras aplicaciones pueden validar tokens sin necesitar la clave privada.

**Esfuerzo:** 0.5 días
**Prioridad:** 🟢 Baja

---

## 📊 Resumen de Prioridades

### Must-Have (para producción)

1. ✅ Email verification
2. ✅ Password reset
3. ✅ Rate limiting
4. ✅ Audit logging (básico)

**Total: 1-2 semanas**

### Should-Have (seguridad mejorada)

5. ✅ MFA/2FA
6. ✅ Session management
7. ✅ JWKS endpoint

**Total: +1-2 semanas**

### Nice-to-Have (features avanzadas)

8. OAuth2 Provider
9. Social Login
10. User management (admin)

**Total: +2-3 semanas**

---

## 🔧 Quick Start para Fase 1

```bash
# 1. Instalar dependencias adicionales
go get github.com/sendgrid/sendgrid-go
go get github.com/pquerna/otp

# 2. Crear archivos necesarios
touch pkg/email/sender.go
touch internal/service/email_service.go
touch internal/repository/token_repository.go
touch internal/repository/postgres/token_postgres.go
touch pkg/ratelimit/limiter.go
touch internal/handler/middleware/ratelimit.go

# 3. Configurar variables de entorno
echo "SENDGRID_API_KEY=your_key" >> .env
echo "EMAIL_FROM=noreply@yourapp.com" >> .env
echo "BASE_URL=http://localhost:8080" >> .env

# 4. Ejecutar
make dev
```

---

## ✅ Checklist de Completitud

### Para considerarse "Production Ready":

- [ ] Email verification implementado
- [ ] Password reset implementado
- [ ] Rate limiting en endpoints críticos
- [ ] Audit logging de eventos de seguridad
- [ ] MFA/2FA disponible (opcional para usuarios)
- [ ] Session management (listar/revocar)
- [ ] HTTPS configurado
- [ ] Secrets en env vars (no hardcoded)
- [ ] Database migrations automated
- [ ] Health checks funcionando
- [ ] Monitoring/alerting configurado
- [ ] Backup strategy definida
- [ ] Disaster recovery plan
- [ ] Load testing realizado
- [ ] Security audit completado

---

**Siguiente paso recomendado:** Empezar con Fase 1.1 (Email Service) ya que es la base para verificación y reset de password.
