# JWT Token con App ID

## ✅ El `app_id` ya está incluido en el token JWT

El sistema **ya incluye automáticamente** el `app_id` en los tokens JWT generados durante el login.

### Estructura del Token JWT

```json
{
  "iss": "auth-service",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "token-uuid",
  "uid": "user-uuid",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "app_id": "7057e69d-818b-45db-b39b-9d1c84aca142",  // ← Aquí está
  "sid": "session-uuid",
  "type": "access"
}
```

## 🔐 Cómo usar el app_id en los handlers

El middleware de autenticación extrae el `app_id` del token y lo pone disponible en `fiber.Locals`:

### Ejemplo en un handler:

```go
func (h *MyHandler) GetData(c *fiber.Ctx) error {
    // Extraer app_id del token (puesto por el middleware)
    appID, ok := c.Locals("app_id").(uuid.UUID)
    if !ok {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "app_id not found in token",
        })
    }

    // Usar el app_id para filtrar datos
    data, err := h.service.GetDataByApp(c.Context(), appID)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    return c.Status(fiber.StatusOK).JSON(data)
}
```

## 📡 Para otros microservicios (Resume Service, etc.)

Los otros microservicios **NO necesitan pedir el app_id al cliente**. Solo deben:

1. **Validar el token JWT** usando el JWKS endpoint
2. **Extraer el app_id** de los claims del token
3. **Usar el app_id** para filtrar datos

### Ejemplo en Go (otro microservicio):

```go
import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
    jwt.RegisteredClaims
    UserID  string   `json:"uid"`
    Email   string   `json:"email"`
    Roles   []string `json:"roles"`
    AppID   string   `json:"app_id"`  // ← Extraer esto
}

// Validar token y extraer app_id
func ValidateAndGetAppID(tokenString string) (string, error) {
    token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Usar JWKS para obtener la clave pública
        return getPublicKeyFromJWKS()
    })

    if err != nil {
        return "", err
    }

    claims, ok := token.Claims.(*CustomClaims)
    if !ok || !token.Valid {
        return "", errors.New("invalid token")
    }

    return claims.AppID, nil  // ← Retornar el app_id
}
```

## 🎯 Beneficios

✅ **Seguridad**: El cliente no puede manipular el app_id (está firmado en el token)
✅ **Simplicidad**: No necesitas pasar app_id en el body de cada request
✅ **Multi-tenant**: Cada microservicio sabe automáticamente a qué app pertenece el usuario
✅ **Consistencia**: Un único source of truth (el token)

## 🔄 Flujo completo

```
1. Usuario hace login
   POST /api/v1/auth/login
   Body: { email, password, app_id }  ← app_id se usa para buscar el usuario

2. Auth Service retorna token JWT
   Response: {
     access_token: "eyJhbGc...",  ← Contiene app_id en los claims
     refresh_token: "eyJhbGc...",
     ...
   }

3. Cliente hace request a cualquier endpoint
   GET /api/v1/users/me
   Header: Authorization: Bearer eyJhbGc...

4. Middleware extrae app_id del token
   c.Locals("app_id") = "7057e69d-818b-45db-b39b-9d1c84aca142"

5. Handler usa el app_id
   appID := c.Locals("app_id").(uuid.UUID)
   user, err := h.service.GetUserByApp(ctx, userID, appID)
```

## 📝 Notas importantes

### Endpoints PÚBLICOS (requieren app_id en el body):
1. **POST /api/v1/auth/register** - Requiere `app_id` (opcional, default: frontend app)
2. **POST /api/v1/auth/login** - Requiere `app_id` (opcional, default: frontend app)
3. **POST /api/v1/auth/forgot-password** - Requiere `app_id` (opcional, default: frontend app)

### Endpoints AUTENTICADOS (app_id viene en el token):
- **Todos los demás endpoints** obtienen el app_id del token automáticamente
- No necesitas enviar app_id en el body
- El middleware lo extrae y lo pone en `c.Locals("app_id")`

### Otras notas:
- **El app_id en el token es inmutable** - si cambias de app, necesitas un nuevo login
- **El app_id por defecto** es `7057e69d-818b-45db-b39b-9d1c84aca142` (CloudCentinel Frontend)

## 🔍 Debugging

Para ver el app_id en los logs:

```
[AUTH_MIDDLEWARE] All checks passed for user: user@example.com (app_id: 7057e69d-818b-45db-b39b-9d1c84aca142)
```

---

**Última actualización:** 2024-12-08
