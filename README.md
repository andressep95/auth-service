# Microservicio de Autenticación en Go

Excelente proyecto. Construir tu propio Identity Provider te da control total y es un ejercicio arquitectónico valioso. Te presento un diseño sólido y pragmático.

---

## Arquitectura General

```
┌─────────────────────────────────────────────────────────────────┐
│                         Clientes                                │
│              (Web Apps, Mobile Apps, APIs)                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API Gateway / Load Balancer                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Auth Service (Go)                             │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────────┐   │
│  │  Auth     │ │  User     │ │  Token    │ │  Session      │   │
│  │  Handler  │ │  Handler  │ │  Service  │ │  Manager      │   │
│  └───────────┘ └───────────┘ └───────────┘ └───────────────┘   │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐                     │
│  │  RBAC     │ │  OAuth2   │ │  MFA      │                     │
│  │  Service  │ │  Provider │ │  Service  │                     │
│  └───────────┘ └───────────┘ └───────────┘                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │PostgreSQL│    │  Redis   │    │  S3/Minio│
    │ (Users)  │    │(Sessions)│    │ (Avatars)│
    └──────────┘    └──────────┘    └──────────┘
```

---

## Estructura del Proyecto

```
auth-service/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── domain/
│   │   ├── user.go
│   │   ├── session.go
│   │   ├── token.go
│   │   └── role.go
│   ├── repository/
│   │   ├── user_repository.go
│   │   ├── session_repository.go
│   │   └── postgres/
│   │       └── user_postgres.go
│   ├── service/
│   │   ├── auth_service.go
│   │   ├── user_service.go
│   │   ├── token_service.go
│   │   └── mfa_service.go
│   ├── handler/
│   │   ├── auth_handler.go
│   │   ├── user_handler.go
│   │   └── middleware/
│   │       ├── auth.go
│   │       └── ratelimit.go
│   └── config/
│       └── config.go
├── pkg/
│   ├── jwt/
│   │   └── jwt.go
│   ├── hash/
│   │   └── argon2.go
│   └── validator/
│       └── validator.go
├── migrations/
│   └── 001_initial.sql
├── docker-compose.yml
├── Dockerfile
└── go.mod
```

---

## Implementación Core

### 1. Dominio - Entidades

```go
// internal/domain/user.go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
)

type User struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Email         string     `json:"email" db:"email"`
	PasswordHash  string     `json:"-" db:"password_hash"`
	FirstName     string     `json:"first_name" db:"first_name"`
	LastName      string     `json:"last_name" db:"last_name"`
	Status        UserStatus `json:"status" db:"status"`
	EmailVerified bool       `json:"email_verified" db:"email_verified"`
	MFAEnabled    bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret     *string    `json:"-" db:"mfa_secret"`
	FailedLogins  int        `json:"-" db:"failed_logins"`
	LockedUntil   *time.Time `json:"-" db:"locked_until"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt   *time.Time `json:"last_login_at" db:"last_login_at"`
}

type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	AppID       uuid.UUID `json:"app_id" db:"app_id"`
}

type Permission struct {
	ID       uuid.UUID `json:"id" db:"id"`
	Name     string    `json:"name" db:"name"`
	Resource string    `json:"resource" db:"resource"`
	Action   string    `json:"action" db:"action"`
}
```

### 2. Servicio de Tokens (JWT)

```go
// pkg/jwt/jwt.go
package jwt

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenService struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	accessExpiry   time.Duration
	refreshExpiry  time.Duration
	issuer         string
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

type Claims struct {
	jwt.RegisteredClaims
	UserID      uuid.UUID `json:"uid"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	AppID       uuid.UUID `json:"app_id,omitempty"`
	TokenType   string    `json:"type"`
}

func NewTokenService(privateKeyPEM, publicKeyPEM []byte, cfg Config) (*TokenService, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return &TokenService{
		privateKey:    privateKey,
		publicKey:     publicKey,
		accessExpiry:  cfg.AccessTokenExpiry,
		refreshExpiry: cfg.RefreshTokenExpiry,
		issuer:        cfg.Issuer,
	}, nil
}

func (s *TokenService) GenerateTokenPair(user *domain.User, roles []string, appID uuid.UUID) (*TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(s.accessExpiry)

	accessClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:    user.ID,
		Email:     user.Email,
		Roles:     roles,
		AppID:     appID,
		TokenType: "access",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	// Refresh token con menos claims
	refreshClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:    user.ID,
		TokenType: "refresh",
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExp,
		TokenType:    "Bearer",
	}, nil
}

func (s *TokenService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
```

### 3. Hash de Passwords (Argon2id)

```go
// pkg/hash/argon2.go
package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultConfig = Argon2Config{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, cfg Argon2Config) (string, error) {
	salt := make([]byte, cfg.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Iterations,
		cfg.Memory,
		cfg.Parallelism,
		cfg.KeyLength,
	)

	// Formato: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, cfg.Memory, cfg.Iterations, cfg.Parallelism,
		b64Salt, b64Hash,
	), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	cfg, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Iterations,
		cfg.Memory,
		cfg.Parallelism,
		cfg.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}
```

### 4. Servicio de Autenticación

```go
// internal/service/auth_service.go
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrMFARequired        = errors.New("mfa verification required")
	ErrInvalidMFACode     = errors.New("invalid mfa code")
)

type AuthService struct {
	userRepo     UserRepository
	sessionRepo  SessionRepository
	tokenService *jwt.TokenService
	mfaService   *MFAService
	cfg          AuthConfig
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	AppID    string `json:"app_id" validate:"required,uuid"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type LoginResponse struct {
	Tokens      *jwt.TokenPair `json:"tokens,omitempty"`
	MFARequired bool           `json:"mfa_required,omitempty"`
	MFAToken    string         `json:"mfa_token,omitempty"`
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verificar si está bloqueado
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	// Verificar password
	valid, err := hash.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		s.handleFailedLogin(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Verificar MFA si está habilitado
	if user.MFAEnabled {
		if req.MFACode == "" {
			// Generar token temporal para MFA
			mfaToken, _ := s.generateMFAToken(user.ID)
			return &LoginResponse{
				MFARequired: true,
				MFAToken:    mfaToken,
			}, nil
		}

		if !s.mfaService.VerifyCode(user.MFASecret, req.MFACode) {
			return nil, ErrInvalidMFACode
		}
	}

	// Reset failed logins
	s.userRepo.ResetFailedLogins(ctx, user.ID)

	// Obtener roles del usuario para esta app
	appID, _ := uuid.Parse(req.AppID)
	roles, _ := s.userRepo.GetUserRoles(ctx, user.ID, appID)

	// Generar tokens
	tokens, err := s.tokenService.GenerateTokenPair(user, roles, appID)
	if err != nil {
		return nil, err
	}

	// Crear sesión
	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    time.Now().Add(s.cfg.RefreshTokenExpiry),
		CreatedAt:    time.Now(),
	}
	s.sessionRepo.Create(ctx, session)

	// Actualizar último login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	return &LoginResponse{Tokens: tokens}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	claims, err := s.tokenService.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Verificar que la sesión exista
	session, err := s.sessionRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("session not found")
	}

	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	roles, _ := s.userRepo.GetUserRoles(ctx, user.ID, claims.AppID)

	// Generar nuevo par de tokens
	newTokens, err := s.tokenService.GenerateTokenPair(user, roles, claims.AppID)
	if err != nil {
		return nil, err
	}

	// Actualizar sesión con nuevo refresh token (rotation)
	session.RefreshToken = newTokens.RefreshToken
	session.ExpiresAt = time.Now().Add(s.cfg.RefreshTokenExpiry)
	s.sessionRepo.Update(ctx, session)

	return newTokens, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.sessionRepo.DeleteByToken(ctx, refreshToken)
}

func (s *AuthService) handleFailedLogin(ctx context.Context, user *domain.User) {
	user.FailedLogins++

	if user.FailedLogins >= s.cfg.MaxFailedLogins {
		lockUntil := time.Now().Add(s.cfg.LockDuration)
		user.LockedUntil = &lockUntil
	}

	s.userRepo.Update(ctx, user)
}
```

### 5. Handlers HTTP

```go
// internal/handler/auth_handler.go
package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authService *service.AuthService
	validator   *validator.Validator
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req service.LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	if err := h.validator.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	resp, err := h.authService.Login(c.Request().Context(), req)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
		case service.ErrAccountLocked:
			return echo.NewHTTPError(http.StatusForbidden, "account is locked")
		case service.ErrInvalidMFACode:
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid mfa code")
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) RefreshToken(c echo.Context) error {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	tokens, err := h.authService.RefreshToken(c.Request().Context(), req.RefreshToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid refresh token")
	}

	return c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c echo.Context) error {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	h.authService.Logout(c.Request().Context(), req.RefreshToken)

	return c.NoContent(http.StatusNoContent)
}
```

### 6. Middleware de Autenticación

```go
// internal/handler/middleware/auth.go
package middleware

import (
	"strings"

	"github.com/labstack/echo/v4"
)

func AuthMiddleware(tokenService *jwt.TokenService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(401, "missing authorization header")
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				return echo.NewHTTPError(401, "invalid authorization format")
			}

			claims, err := tokenService.ValidateToken(parts[1])
			if err != nil {
				return echo.NewHTTPError(401, "invalid token")
			}

			if claims.TokenType != "access" {
				return echo.NewHTTPError(401, "invalid token type")
			}

			// Guardar claims en context
			c.Set("user_id", claims.UserID)
			c.Set("email", claims.Email)
			c.Set("roles", claims.Roles)
			c.Set("claims", claims)

			return next(c)
		}
	}
}

func RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userRoles, ok := c.Get("roles").([]string)
			if !ok {
				return echo.NewHTTPError(403, "forbidden")
			}

			for _, required := range roles {
				for _, userRole := range userRoles {
					if userRole == required {
						return next(c)
					}
				}
			}

			return echo.NewHTTPError(403, "insufficient permissions")
		}
	}
}
```

---

## Endpoints API

| Método | Endpoint                           | Descripción                   |
| ------ | ---------------------------------- | ----------------------------- |
| `POST` | `/api/v1/auth/register`            | Registro de usuario           |
| `POST` | `/api/v1/auth/login`               | Login (retorna tokens)        |
| `POST` | `/api/v1/auth/refresh`             | Refresh token                 |
| `POST` | `/api/v1/auth/logout`              | Logout (invalida refresh)     |
| `POST` | `/api/v1/auth/forgot-password`     | Solicitar reset               |
| `POST` | `/api/v1/auth/reset-password`      | Resetear password             |
| `GET`  | `/api/v1/auth/verify-email/:token` | Verificar email               |
| `POST` | `/api/v1/auth/mfa/setup`           | Configurar MFA                |
| `POST` | `/api/v1/auth/mfa/verify`          | Verificar código MFA          |
| `GET`  | `/api/v1/users/me`                 | Perfil del usuario            |
| `PUT`  | `/api/v1/users/me`                 | Actualizar perfil             |
| `GET`  | `/.well-known/jwks.json`           | Public keys (para validación) |

---

## Migración SQL Base

```sql
-- migrations/001_initial.sql

-- Apps registradas
CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(64) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    redirect_uris TEXT[],
    allowed_scopes TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Usuarios
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);

-- Roles por aplicación
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    UNIQUE(app_id, name)
);

-- Permisos
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    UNIQUE(resource, action)
);

-- Roles-Permisos
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Usuarios-Roles (por app)
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Sesiones (para refresh tokens)
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

---

## Docker Compose para Desarrollo

```yaml
version: "3.8"

services:
  auth-service:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://auth:auth@postgres:5432/authdb?sslmode=disable
      - REDIS_URL=redis://redis:6379
      - JWT_PRIVATE_KEY_PATH=/keys/private.pem
      - JWT_PUBLIC_KEY_PATH=/keys/public.pem
    volumes:
      - ./keys:/keys:ro
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: auth
      POSTGRES_PASSWORD: auth
      POSTGRES_DB: authdb
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

---

## Recomendaciones de Seguridad

| Aspecto             | Implementación                                 |
| ------------------- | ---------------------------------------------- |
| **Passwords**       | Argon2id con salt único                        |
| **Tokens**          | RS256 (asimétrico) para validación distribuida |
| **Refresh Tokens**  | Rotación en cada uso + almacenamiento hasheado |
| **Rate Limiting**   | Por IP y por usuario en endpoints críticos     |
| **Account Lockout** | Después de N intentos fallidos                 |
| **MFA**             | TOTP (compatible con Google Authenticator)     |
| **HTTPS**           | Obligatorio en producción                      |
| **CORS**            | Configuración estricta por app                 |

---

## Librerías Recomendadas

```go
// go.mod
require (
    github.com/labstack/echo/v4 v4.11.4
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/google/uuid v1.6.0
    github.com/jmoiron/sqlx v1.3.5
    github.com/lib/pq v1.10.9
    github.com/redis/go-redis/v9 v9.4.0
    github.com/pquerna/otp v1.4.0      // Para TOTP/MFA
    golang.org/x/crypto v0.18.0        // Argon2
    github.com/go-playground/validator/v10 v10.17.0
)
```

---

¿Quieres que profundice en algún componente específico? Por ejemplo:

- **OAuth2/OIDC completo** (authorization code flow, PKCE)
- **Multi-tenancy** (usuarios compartidos entre apps)
- **Event sourcing** para audit logs
- **Despliegue en AWS** (ECS, RDS, ElastiCache)
