# JWKS - JSON Web Key Set

## 🤔 ¿Qué es JWKS?

**JWKS** (JSON Web Key Set) es un **endpoint estándar** que expone las claves públicas en formato JSON para que otros servicios puedan validar tokens JWT automáticamente.

## 🔄 Problema Actual vs Solución JWKS

### ❌ Problema Actual (Sin JWKS)

```
Backend 1 (Node.js)  ──┐
Backend 2 (Python)   ──┼──> Necesitan copiar manualmente
Backend 3 (Go)       ──┤    el archivo public.pem
Backend 4 (Java)     ──┘
```

**Problemas:**
1. Debes copiar `public.pem` a cada backend manualmente
2. Si rotas claves, debes actualizar TODOS los backends
3. Nuevos servicios necesitan configuración manual
4. No hay forma automática de obtener claves

### ✅ Solución con JWKS

```
Backend 1 ──┐
Backend 2 ──┼──> GET https://auth.com/.well-known/jwks.json
Backend 3 ──┤    (Obtienen claves automáticamente)
Backend 4 ──┘
```

**Ventajas:**
1. ✅ Backends obtienen claves automáticamente vía HTTP
2. ✅ Rotación de claves sin downtime
3. ✅ Nuevos servicios se auto-configuran
4. ✅ Estándar de la industria (OAuth2/OIDC)

---

## 📋 Formato JWKS

### Endpoint

```
GET https://auth-service.com/.well-known/jwks.json
```

### Respuesta

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-12-01",
      "alg": "RS256",
      "n": "xGOr-H7A...base64...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig", 
      "kid": "2024-11-01",
      "alg": "RS256",
      "n": "yH8s-K9B...base64...",
      "e": "AQAB"
    }
  ]
}
```

**Campos importantes:**
- `kid` (Key ID): Identificador único de la clave
- `n`: Módulo de la clave RSA (base64)
- `e`: Exponente público (usualmente "AQAB")
- `alg`: Algoritmo (RS256)

---

## 🔑 Rotación de Claves con JWKS

### Sin JWKS (Actual)

```
1. Generas nueva clave
2. ❌ DOWNTIME: Todos los tokens se invalidan
3. Copias public.pem a TODOS los backends
4. Reinicias TODOS los servicios
5. Sistema vuelve a funcionar
```

### Con JWKS (Futuro)

```
1. Generas nueva clave (kid: "2024-12-01")
2. Publicas AMBAS claves en JWKS:
   - Clave vieja (kid: "2024-11-01") 
   - Clave nueva (kid: "2024-12-01")
3. ✅ NO HAY DOWNTIME
   - Tokens viejos → validados con clave vieja
   - Tokens nuevos → validados con clave nueva
4. Después de 15 min (expiración), eliminas clave vieja
```

**Flujo:**

```
10:00 - Clave actual: key-nov
        JWKS: [key-nov]
        
10:05 - Generas key-dec
        JWKS: [key-nov, key-dec]  ← Ambas activas
        Auth Service emite tokens con key-dec
        
10:06 - Token viejo (firmado con key-nov) → ✅ Válido
        Token nuevo (firmado con key-dec) → ✅ Válido
        
10:20 - Todos los tokens viejos expiraron (15 min)
        JWKS: [key-dec]  ← Eliminas key-nov
```

---

## 💻 Implementación

### 1. Auth Service (Exponer JWKS)

```go
// internal/handler/jwks_handler.go
package handler

import (
    "crypto/rsa"
    "encoding/base64"
    "math/big"
    "github.com/gofiber/fiber/v2"
)

type JWKSHandler struct {
    publicKey *rsa.PublicKey
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

type JWK struct {
    Kty string `json:"kty"` // "RSA"
    Use string `json:"use"` // "sig"
    Kid string `json:"kid"` // Key ID
    Alg string `json:"alg"` // "RS256"
    N   string `json:"n"`   // Modulus (base64)
    E   string `json:"e"`   // Exponent (base64)
}

func (h *JWKSHandler) GetJWKS(c *fiber.Ctx) error {
    // Convertir clave pública RSA a formato JWK
    n := base64.RawURLEncoding.EncodeToString(h.publicKey.N.Bytes())
    e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.publicKey.E)).Bytes())
    
    jwks := JWKS{
        Keys: []JWK{
            {
                Kty: "RSA",
                Use: "sig",
                Kid: "2024-12-01", // Versión de la clave
                Alg: "RS256",
                N:   n,
                E:   e,
            },
        },
    }
    
    return c.JSON(jwks)
}

// routes.go
app.Get("/.well-known/jwks.json", jwksHandler.GetJWKS)
```

### 2. Backend (Consumir JWKS)

#### Node.js

```javascript
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

// Cliente JWKS (cachea claves automáticamente)
const client = jwksClient({
  jwksUri: 'http://auth-service:8080/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 600000, // 10 minutos
  rateLimit: true
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}
```

#### Python (FastAPI)

```python
from jose import jwt
from jose.backends import RSAKey
import requests

class JWKSClient:
    def __init__(self, jwks_url):
        self.jwks_url = jwks_url
        self.keys = {}
        self.refresh_keys()
    
    def refresh_keys(self):
        response = requests.get(self.jwks_url)
        jwks = response.json()
        
        for key in jwks['keys']:
            self.keys[key['kid']] = RSAKey(key, algorithm='RS256')
    
    def get_key(self, kid):
        if kid not in self.keys:
            self.refresh_keys()
        return self.keys.get(kid)

# Inicializar
jwks_client = JWKSClient('http://auth-service:8080/.well-known/jwks.json')

# Middleware
def verify_token(token: str):
    header = jwt.get_unverified_header(token)
    kid = header['kid']
    
    key = jwks_client.get_key(kid)
    if not key:
        raise ValueError('Key not found')
    
    payload = jwt.decode(token, key, algorithms=['RS256'])
    return payload
```

#### Go

```go
import (
    "github.com/lestrrat-go/jwx/jwk"
    "github.com/lestrrat-go/jwx/jwt"
)

// Obtener keyset
keySet, _ := jwk.Fetch(context.Background(), 
    "http://auth-service:8080/.well-known/jwks.json")

// Validar token
token, err := jwt.Parse(
    []byte(tokenString),
    jwt.WithKeySet(keySet),
)
```

---

## 🌟 Por qué es Importante

### 1. **Escalabilidad**

```
Sin JWKS:
  Agregar Backend 10 → Copiar archivo, configurar, reiniciar

Con JWKS:
  Agregar Backend 10 → Solo configurar URL del JWKS
```

### 2. **Seguridad**

```
Sin JWKS:
  Clave comprometida → Pánico, downtime, actualización manual

Con JWKS:
  Clave comprometida → Rotas en segundos, sin downtime
```

### 3. **Microservicios**

```
10 microservicios × 3 ambientes = 30 configuraciones manuales ❌

Con JWKS:
  1 URL configurada = Todos los servicios actualizados ✅
```

### 4. **Estándar de la Industria**

Todos los grandes proveedores usan JWKS:
- Google: `https://www.googleapis.com/oauth2/v3/certs`
- Auth0: `https://{tenant}.auth0.com/.well-known/jwks.json`
- AWS Cognito: `https://cognito-idp.{region}.amazonaws.com/{poolId}/.well-known/jwks.json`
- Microsoft: `https://login.microsoftonline.com/common/discovery/v2.0/keys`

---

## 🚀 Cuándo Implementar JWKS

### Ahora (Sin JWKS) - OK para:
- ✅ Desarrollo local
- ✅ 1-3 backends
- ✅ Prototipo/MVP
- ✅ Claves estáticas

### Futuro (Con JWKS) - Necesario para:
- ⚠️ Producción con múltiples servicios
- ⚠️ Rotación de claves frecuente
- ⚠️ Equipos distribuidos
- ⚠️ Compliance/Auditoría
- ⚠️ Multi-tenant

---

## 📊 Comparación

| Aspecto | Sin JWKS | Con JWKS |
|---------|----------|----------|
| **Setup inicial** | Fácil (copiar archivo) | Medio (implementar endpoint) |
| **Agregar backend** | Manual | Automático |
| **Rotación de claves** | Downtime | Sin downtime |
| **Escalabilidad** | Baja | Alta |
| **Mantenimiento** | Alto | Bajo |
| **Estándar** | No | Sí (OAuth2/OIDC) |
| **Caché** | No | Sí (automático) |

---

## 🎯 Roadmap Sugerido

### Fase 1 (Actual) ✅
- Copiar `public.pem` manualmente
- 1-3 backends
- Desarrollo/Staging

### Fase 2 (Próximo) 🔄
- Implementar endpoint JWKS
- Backends consumen JWKS
- Preparar rotación de claves

### Fase 3 (Futuro) 🚀
- Rotación automática de claves
- Múltiples claves activas
- Monitoreo de uso de claves
- Revocación de claves comprometidas

---

## 💡 Ejemplo Real

### Google OAuth

```bash
# Ver JWKS de Google
curl https://www.googleapis.com/oauth2/v3/certs

{
  "keys": [
    {
      "kid": "a1b2c3d4e5f6",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "xGOr...",
      "e": "AQAB"
    },
    {
      "kid": "f6e5d4c3b2a1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "yH8s...",
      "e": "AQAB"
    }
  ]
}
```

Google rota claves regularmente y **nunca hay downtime** porque:
1. Publican nueva clave en JWKS
2. Mantienen clave vieja activa
3. Después de expiración, eliminan clave vieja

---

## 🔗 Referencias

- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

---

## ✅ Resumen

**JWKS es importante porque:**

1. 🔄 **Automatiza** la distribución de claves públicas
2. 🔒 **Permite** rotación de claves sin downtime
3. 📈 **Escala** a cientos de microservicios
4. 🌍 **Estándar** usado por toda la industria
5. 🚀 **Simplifica** agregar nuevos servicios

**No es urgente ahora, pero será crítico cuando:**
- Tengas 5+ microservicios
- Necesites rotar claves regularmente
- Vayas a producción con alta disponibilidad
- Necesites compliance (SOC2, ISO27001)
