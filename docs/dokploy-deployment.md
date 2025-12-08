# Despliegue en Dokploy (Contabo) - Guía Definitiva

## 🎯 Solución para Dokploy

**Problema resuelto:** Las claves RSA se generan **automáticamente** dentro del contenedor al iniciar. No necesitas volúmenes ni configuración manual.

```
✅ Claves se generan automáticamente al iniciar
✅ JWKS expone las claves vía HTTP
✅ Backends obtienen claves del endpoint JWKS
✅ Sin volúmenes, sin archivos compartidos
✅ 100% compatible con Dockerfile en Dokploy
```

---

## 📋 Paso 1: Desplegar Auth Service en Dokploy

### 1. Crear Servicio en Dokploy

- **Tipo:** GitHub/Docker
- **Nombre:** `auth-service`
- **Puerto:** `8080`
- **Dockerfile:** `Dockerfile` (en la raíz del repo)

### 2. Variables de Entorno

```bash
# Server
SERVER_PORT=8080
ENVIRONMENT=production

# Database (PostgreSQL de Dokploy)
DB_HOST=<tu-postgres-host>
DB_PORT=5432
DB_USER=auth
DB_PASSWORD=<password-seguro>
DB_NAME=authdb
DB_SSLMODE=require

# Redis (Redis de Dokploy)
REDIS_HOST=<tu-redis-host>
REDIS_PORT=6379
REDIS_PASSWORD=<password-redis>
REDIS_DB=0

# JWT (las claves se generan automáticamente)
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
JWT_ISSUER=auth-service

# CORS (tus dominios)
CORS_ALLOWED_ORIGINS=https://app.tudominio.com,https://admin.tudominio.com

# Email (Resend)
EMAIL_ENABLED=true
EMAIL_PROVIDER=resend
EMAIL_API_KEY=<tu-resend-api-key>
EMAIL_FROM_EMAIL=noreply@tudominio.com
EMAIL_FROM_NAME=Tu App
EMAIL_BASE_URL=https://app.tudominio.com
EMAIL_VERIFICATION_URL=https://app.tudominio.com/verify-email
EMAIL_RESET_URL=https://app.tudominio.com/reset-password
```

### 3. Configurar Dominio

- **Dominio:** `auth.tudominio.com`
- **SSL:** Automático (Let's Encrypt)

### 4. Deploy

```bash
# Dokploy detecta el Dockerfile y construye automáticamente
# Al iniciar, el contenedor:
# 1. Genera claves RSA si no existen
# 2. Inicia el servidor
# 3. Expone JWKS en /.well-known/jwks.json
```

---

## 🔄 ¿Cómo Funciona?

### Flujo de Inicio del Contenedor

```
1. Container inicia
2. docker-entrypoint.sh ejecuta
3. Verifica si existen /app/keys/private.pem y public.pem
4. Si NO existen → Genera claves RSA 4096 bits
5. Si SÍ existen → Usa las existentes
6. Inicia aplicación Go
7. JWKS endpoint disponible en /.well-known/jwks.json
```

### Persistencia de Claves

**Opción 1: Volumen Persistente (Recomendado)**

En Dokploy, agregar volumen:

```
/app/keys → Volumen persistente
```

Esto mantiene las mismas claves entre reinicios.

**Opción 2: Sin Volumen (Desarrollo)**

Las claves se regeneran en cada deploy. Los tokens antiguos se invalidan.

---

## 📋 Paso 2: Desplegar Backend (Node.js)

### Dockerfile

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Instalar dependencias
COPY package*.json ./
RUN npm ci --only=production

# Copiar código
COPY . .

EXPOSE 4000

CMD ["node", "server.js"]
```

### Variables de Entorno en Dokploy

```bash
PORT=4000
NODE_ENV=production

# ⭐ SOLO NECESITAS ESTO PARA AUTH
AUTH_JWKS_URL=https://auth.tudominio.com/.well-known/jwks.json

# Tu base de datos
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

### Código del Backend

```javascript
// middleware/auth.js
const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");

// Cliente JWKS - obtiene claves automáticamente del Auth Service
const client = jwksClient({
  jwksUri: process.env.AUTH_JWKS_URL,
  cache: true,
  cacheMaxAge: 600000, // 10 minutos
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = {
      id: decoded.uid,
      email: decoded.email,
      roles: decoded.roles || [],
    };

    next();
  });
}

module.exports = { authenticate };

// server.js
const express = require("express");
const { authenticate } = require("./middleware/auth");

const app = express();

app.get("/api/products", authenticate, (req, res) => {
  // req.user contiene la info del token
  console.log("User:", req.user.id, req.user.email);
  res.json({ products: [] });
});

app.listen(4000, () => console.log("Server running on port 4000"));
```

### package.json

```json
{
  "name": "backend-api",
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "jwks-rsa": "^3.1.0"
  }
}
```

---

## 📋 Paso 3: Desplegar Frontend (React)

### Dockerfile

```dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### Variables de Entorno en Dokploy

```bash
REACT_APP_AUTH_URL=https://auth.tudominio.com
REACT_APP_API_URL=https://api.tudominio.com
REACT_APP_APP_ID=7057e69d-818b-45db-b39b-9d1c84aca142
```

### Código del Frontend

```javascript
// src/services/auth.js
const AUTH_API = process.env.REACT_APP_AUTH_URL;
const APP_ID = process.env.REACT_APP_APP_ID;

export async function login(email, password) {
  const response = await fetch(`${AUTH_API}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, app_id: APP_ID }),
  });

  if (!response.ok) throw new Error("Login failed");

  const data = await response.json();

  localStorage.setItem("access_token", data.tokens.access_token);
  localStorage.setItem("refresh_token", data.tokens.refresh_token);

  return data;
}

export function logout() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

export function getToken() {
  return localStorage.getItem("access_token");
}

// src/services/api.js
import { getToken, logout } from "./auth";

const API_URL = process.env.REACT_APP_API_URL;

export async function apiRequest(endpoint, options = {}) {
  const token = getToken();

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (response.status === 401) {
    logout();
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  return response.json();
}

// Ejemplo de uso
import { apiRequest } from "./services/api";

async function getProducts() {
  const data = await apiRequest("/api/products");
  return data.products;
}
```

---

## 🧪 Verificación Post-Deploy

### 1. Verificar Auth Service

```bash
# Health check
curl https://auth.tudominio.com/health

# JWKS endpoint
curl https://auth.tudominio.com/.well-known/jwks.json

# Deberías ver:
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "kid": "2024-12-01",
    "alg": "RS256",
    "n": "xGOr...",
    "e": "AQAB"
  }]
}
```

### 2. Probar Login

```bash
curl -X POST https://auth.tudominio.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "Admin123!",
    "app_id": "7057e69d-818b-45db-b39b-9d1c84aca142"
  }'

# Guarda el access_token de la respuesta
```

### 3. Probar Backend con Token

```bash
TOKEN="<access_token_del_paso_anterior>"

curl https://api.tudominio.com/api/products \
  -H "Authorization: Bearer $TOKEN"

# Debería retornar datos (no 401)
```

---

## 🔄 Rotación Automática de Claves (Opcional)

### Opción 1: Manual (Recomendado para empezar)

```bash
# Cada 3-6 meses
1. Redeploy del auth-service en Dokploy
2. Las claves se regeneran automáticamente
3. JWKS se actualiza automáticamente
4. Backends obtienen nuevas claves automáticamente
```

### Opción 2: Automática con Cron (Futuro)

```go
// internal/service/key_rotation_service.go
package service

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"
    "time"
)

type KeyRotationService struct {
    privateKeyPath string
    publicKeyPath  string
    rotationPeriod time.Duration
}

func (s *KeyRotationService) StartAutoRotation() {
    ticker := time.NewTicker(s.rotationPeriod)

    go func() {
        for range ticker.C {
            s.rotateKeys()
        }
    }()
}

func (s *KeyRotationService) rotateKeys() error {
    // Generar nueva clave
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return err
    }

    // Guardar clave privada
    privateFile, _ := os.Create(s.privateKeyPath)
    defer privateFile.Close()

    pem.Encode(privateFile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    // Guardar clave pública
    publicFile, _ := os.Create(s.publicKeyPath)
    defer publicFile.Close()

    publicBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    pem.Encode(publicFile, &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicBytes,
    })

    // Recargar TokenService con nuevas claves
    // (implementar lógica de recarga)

    return nil
}
```

---

## 🏗️ Arquitectura Final en Dokploy

```
┌─────────────────────────────────────────────────────────┐
│                    Internet                             │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Dokploy (Contabo VPS)                      │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  auth.tudominio.com (Auth Service)               │  │
│  │  - Puerto: 8080                                  │  │
│  │  - Claves RSA auto-generadas                    │  │
│  │  - JWKS: /.well-known/jwks.json                 │  │
│  └──────────────────────────────────────────────────┘  │
│                     ▲                                   │
│                     │ JWKS                              │
│  ┌──────────────────┴───────────────────────────────┐  │
│  │  api.tudominio.com (Backend API)                 │  │
│  │  - Puerto: 4000                                  │  │
│  │  - Obtiene claves de JWKS                       │  │
│  │  - Valida tokens automáticamente                │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  app.tudominio.com (Frontend)                    │  │
│  │  - Puerto: 80                                    │  │
│  │  - Envía tokens al backend                      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  PostgreSQL (Base de datos)                     │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Redis (Cache y Blacklist)                      │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## ✅ Checklist de Despliegue

### Auth Service

- [ ] Repo conectado en Dokploy
- [ ] Variables de entorno configuradas
- [ ] Dominio `auth.tudominio.com` configurado
- [ ] SSL activo (Let's Encrypt)
- [ ] Volumen `/app/keys` configurado (opcional pero recomendado)
- [ ] Deploy exitoso
- [ ] Endpoint `/.well-known/jwks.json` accesible
- [ ] Migraciones ejecutadas (conectar a DB y ejecutar)
- [ ] Usuario admin creado

### Backend API

- [ ] Dockerfile creado
- [ ] Variable `AUTH_JWKS_URL` configurada
- [ ] Dependencia `jwks-rsa` instalada
- [ ] Middleware de autenticación implementado
- [ ] Dominio `api.tudominio.com` configurado
- [ ] SSL activo
- [ ] Deploy exitoso
- [ ] Prueba con token funciona

### Frontend

- [ ] Dockerfile creado
- [ ] Variables `REACT_APP_*` configuradas
- [ ] Servicio de auth implementado
- [ ] Interceptor de tokens implementado
- [ ] Dominio `app.tudominio.com` configurado
- [ ] SSL activo
- [ ] Deploy exitoso
- [ ] Login funciona end-to-end

---

## 🆘 Troubleshooting

### Error: "Failed to generate keys"

```bash
# Ver logs en Dokploy
# Verificar que openssl está instalado en el contenedor
# El Dockerfile ya incluye: RUN apk add openssl
```

### Error: "JWKS endpoint returns 404"

```bash
# Verificar que el servicio está corriendo
curl https://auth.tudominio.com/health

# Verificar logs
# Buscar: "Server starting on"
```

### Error: "Invalid token signature" en Backend

```bash
# Verificar que AUTH_JWKS_URL es correcta
echo $AUTH_JWKS_URL

# Debe ser: https://auth.tudominio.com/.well-known/jwks.json

# Reiniciar backend para limpiar cache
```

### Error: "CORS policy" en Frontend

```bash
# Agregar dominio del frontend a CORS_ALLOWED_ORIGINS
CORS_ALLOWED_ORIGINS=https://app.tudominio.com

# Redeploy auth-service
```

---

## 🎯 Ventajas de Esta Arquitectura

```
✅ Sin archivos compartidos entre contenedores
✅ Sin volúmenes complejos
✅ Claves se generan automáticamente
✅ JWKS distribuye claves vía HTTP
✅ Backends se auto-configuran
✅ Agregar servicios = 1 variable de entorno
✅ Rotación de claves sin downtime
✅ 100% compatible con Dokploy
✅ Escalable a N microservicios
```

---

## 📚 Próximos Pasos

1. **Deploy Auth Service** → Verificar JWKS
2. **Deploy Backend** → Probar con token
3. **Deploy Frontend** → Probar login end-to-end
4. **Monitoreo** → Configurar alertas en Dokploy
5. **Backup** → Configurar backup de PostgreSQL
6. **Rotación** → Planificar rotación de claves (cada 3-6 meses)

---

**¿Dudas?** Todo está automatizado. Solo necesitas configurar variables de entorno en Dokploy y hacer deploy.
