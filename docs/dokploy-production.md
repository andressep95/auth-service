# Despliegue en Dokploy/Contabo - Guía de Producción

## 🎯 Realidad de Dokploy

En Dokploy con Dockerfile:

- ❌ No hay docker-compose
- ❌ No hay volúmenes compartidos entre servicios
- ❌ Cada servicio es un contenedor aislado
- ✅ Cada servicio tiene su propio Dockerfile
- ✅ Variables de entorno por servicio
- ✅ Comunicación vía HTTP (dominios públicos)

## 💡 Solución Real para Producción

### Arquitectura

```
Auth Service (auth.tudominio.com)
    ↓ Genera claves RSA al iniciar
    ↓ Expone JWKS en /.well-known/jwks.json

Backend 1 (api.tudominio.com)
    ↓ Obtiene claves de https://auth.tudominio.com/.well-known/jwks.json
    ↓ Valida tokens

Backend 2 (admin-api.tudominio.com)
    ↓ Obtiene claves de https://auth.tudominio.com/.well-known/jwks.json
    ↓ Valida tokens
```

**Clave:** Todo vía HTTP público. Sin archivos compartidos.

---

## 📋 Paso 1: Auth Service en Dokploy

### Dockerfile (ya está listo)

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git openssl
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/main.go

FROM alpine:latest
WORKDIR /app
RUN apk --no-cache add openssl ca-certificates
COPY --from=builder /app/main .
COPY migrations ./migrations
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh
RUN mkdir -p /app/keys
EXPOSE 8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["./main"]
```

### En Dokploy

1. **Crear Servicio**

   - Tipo: GitHub
   - Repositorio: tu-repo/auth-service
   - Branch: main
   - Build Type: Dockerfile

2. **Variables de Entorno**

```bash
SERVER_PORT=8080
ENVIRONMENT=production

# PostgreSQL (crear en Dokploy primero)
DB_HOST=postgres-auth.dokploy.internal
DB_PORT=5432
DB_USER=auth
DB_PASSWORD=TuPasswordSeguro123!
DB_NAME=authdb
DB_SSLMODE=disable

# Redis (crear en Dokploy primero)
REDIS_HOST=redis-auth.dokploy.internal
REDIS_PORT=6379
REDIS_PASSWORD=TuRedisPassword123!
REDIS_DB=0

# JWT (se generan automáticamente)
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
JWT_ISSUER=auth-service

# CORS
CORS_ALLOWED_ORIGINS=https://app.tudominio.com,https://admin.tudominio.com

# Email
EMAIL_ENABLED=true
EMAIL_PROVIDER=resend
EMAIL_API_KEY=re_tu_api_key
EMAIL_FROM_EMAIL=noreply@tudominio.com
EMAIL_FROM_NAME=Tu App
```

3. **Dominio**

   - Agregar: `auth.tudominio.com`
   - SSL: Automático

4. **Volumen Persistente (IMPORTANTE)**

En Dokploy, agregar volumen:

```
Source: auth-keys (crear volumen)
Target: /app/keys
```

Esto mantiene las mismas claves entre reinicios/redeploys.

5. **Deploy**

Click en "Deploy" → Esperar build → Verificar logs

---

## 📋 Paso 2: Backend Node.js en Dokploy

### Estructura del Proyecto

```
backend-api/
├── Dockerfile
├── package.json
├── server.js
└── middleware/
    └── auth.js
```

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

### package.json

```json
{
  "name": "backend-api",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2",
    "jwks-rsa": "^3.1.0",
    "pg": "^8.11.3"
  }
}
```

### middleware/auth.js

```javascript
const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");

// Cliente JWKS - obtiene claves del Auth Service
const client = jwksClient({
  jwksUri: process.env.AUTH_JWKS_URL,
  cache: true,
  cacheMaxAge: 600000, // 10 minutos
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      console.error("Error getting signing key:", err);
      return callback(err);
    }
    callback(null, key.getPublicKey());
  });
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.substring(7);

  jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", err.message);
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

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const hasRole = allowedRoles.some((role) => req.user.roles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: "Forbidden",
        required_roles: allowedRoles,
      });
    }

    next();
  };
}

module.exports = { authenticate, requireRole };
```

### server.js

```javascript
const express = require("express");
const cors = require("cors");
const { authenticate, requireRole } = require("./middleware/auth");

const app = express();

app.use(cors());
app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Rutas públicas
app.get("/api/public", (req, res) => {
  res.json({ message: "Public endpoint" });
});

// Rutas protegidas
app.get("/api/products", authenticate, (req, res) => {
  console.log("User:", req.user.id, req.user.email);
  res.json({
    products: [],
    user: req.user,
  });
});

// Rutas admin
app.post("/api/products", authenticate, requireRole("admin"), (req, res) => {
  res.json({ message: "Product created" });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`JWKS URL: ${process.env.AUTH_JWKS_URL}`);
});
```

### En Dokploy

1. **Crear Servicio**

   - Tipo: GitHub
   - Repositorio: tu-repo/backend-api
   - Build Type: Dockerfile

2. **Variables de Entorno**

```bash
PORT=4000
NODE_ENV=production

# Auth Service (JWKS)
AUTH_JWKS_URL=https://auth.tudominio.com/.well-known/jwks.json

# Database
DATABASE_URL=postgresql://user:pass@postgres.dokploy.internal:5432/mydb
```

3. **Dominio**

   - Agregar: `api.tudominio.com`

4. **Deploy**

---

## 📋 Paso 3: Frontend React en Dokploy

### Estructura

```
frontend/
├── Dockerfile
├── nginx.conf
├── package.json
└── src/
    ├── services/
    │   ├── auth.js
    │   └── api.js
    └── ...
```

### Dockerfile

```dockerfile
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build con variables de entorno
ARG REACT_APP_AUTH_URL
ARG REACT_APP_API_URL
ARG REACT_APP_APP_ID

ENV REACT_APP_AUTH_URL=$REACT_APP_AUTH_URL
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_APP_ID=$REACT_APP_APP_ID

RUN npm run build

# Production stage
FROM nginx:alpine

COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### nginx.conf

```nginx
server {
    listen 80;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### src/services/auth.js

```javascript
const AUTH_API = process.env.REACT_APP_AUTH_URL;
const APP_ID = process.env.REACT_APP_APP_ID;

export async function login(email, password) {
  const response = await fetch(`${AUTH_API}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, app_id: APP_ID }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Login failed");
  }

  const data = await response.json();

  localStorage.setItem("access_token", data.tokens.access_token);
  localStorage.setItem("refresh_token", data.tokens.refresh_token);

  return data;
}

export async function refreshToken() {
  const refresh = localStorage.getItem("refresh_token");

  const response = await fetch(`${AUTH_API}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });

  if (!response.ok) throw new Error("Refresh failed");

  const data = await response.json();

  localStorage.setItem("access_token", data.access_token);
  localStorage.setItem("refresh_token", data.refresh_token);

  return data.access_token;
}

export function logout() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

export function getToken() {
  return localStorage.getItem("access_token");
}
```

### src/services/api.js

```javascript
import { getToken, refreshToken, logout } from "./auth";

const API_URL = process.env.REACT_APP_API_URL;

export async function apiRequest(endpoint, options = {}) {
  let token = getToken();

  const makeRequest = async (token) => {
    return fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
  };

  let response = await makeRequest(token);

  // Si token expiró, intentar refresh
  if (response.status === 401) {
    try {
      token = await refreshToken();
      response = await makeRequest(token);
    } catch (error) {
      logout();
      window.location.href = "/login";
      throw error;
    }
  }

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Request failed");
  }

  return response.json();
}
```

### En Dokploy

1. **Crear Servicio**

   - Tipo: GitHub
   - Build Type: Dockerfile

2. **Build Args (IMPORTANTE)**

```bash
REACT_APP_AUTH_URL=https://auth.tudominio.com
REACT_APP_API_URL=https://api.tudominio.com
REACT_APP_APP_ID=00000000-0000-0000-0000-000000000000
```

3. **Dominio**

   - Agregar: `app.tudominio.com`

4. **Deploy**

---

## 🧪 Verificación Completa

### 1. Auth Service

```bash
# Health
curl https://auth.tudominio.com/health

# JWKS
curl https://auth.tudominio.com/.well-known/jwks.json

# Login
curl -X POST https://auth.tudominio.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "Admin123!",
    "app_id": "00000000-0000-0000-0000-000000000000"
  }'
```

### 2. Backend

```bash
# Con token del login anterior
TOKEN="eyJhbGc..."

curl https://api.tudominio.com/api/products \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Frontend

Abrir `https://app.tudominio.com` en navegador y probar login.

---

## 🔒 Persistencia de Claves (CRÍTICO)

### Problema

Sin volumen persistente, las claves se regeneran en cada deploy:

- ❌ Todos los tokens se invalidan
- ❌ Usuarios deben hacer login nuevamente

### Solución en Dokploy

**Opción 1: Volumen Persistente (Recomendado)**

En Dokploy → Auth Service → Volumes:

```
Name: auth-keys
Mount Path: /app/keys
```

Esto mantiene las claves entre deploys.

**Opción 2: Variables de Entorno (Alternativa)**

Generar claves una vez y guardarlas como variables:

```bash
# Generar localmente
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# Convertir a base64
PRIVATE_KEY_BASE64=$(cat private.pem | base64)
PUBLIC_KEY_BASE64=$(cat public.pem | base64)
```

En Dokploy, agregar variables:

```bash
JWT_PRIVATE_KEY_BASE64=LS0tLS1CRUdJTi...
JWT_PUBLIC_KEY_BASE64=LS0tLS1CRUdJTi...
```

Modificar `docker-entrypoint.sh`:

```bash
if [ -n "$JWT_PRIVATE_KEY_BASE64" ]; then
    echo "$JWT_PRIVATE_KEY_BASE64" | base64 -d > /app/keys/private.pem
    echo "$JWT_PUBLIC_KEY_BASE64" | base64 -d > /app/keys/public.pem
fi
```

---

## 📊 Arquitectura Final

```
Internet
    ↓
Dokploy/Contabo VPS
    ↓
┌─────────────────────────────────────────┐
│ auth.tudominio.com                      │
│ - Genera claves al iniciar              │
│ - Expone JWKS                           │
│ - Volumen: /app/keys (persistente)     │
└─────────────────────────────────────────┘
    ↓ HTTPS
┌─────────────────────────────────────────┐
│ api.tudominio.com                       │
│ - Obtiene claves de JWKS                │
│ - Valida tokens                         │
│ - Sin archivos locales                  │
└─────────────────────────────────────────┘
    ↓ HTTPS
┌─────────────────────────────────────────┐
│ app.tudominio.com                       │
│ - Envía tokens al backend               │
│ - Refresh automático                    │
└─────────────────────────────────────────┘
```

---

## ✅ Checklist Final

### Antes de Deploy

- [ ] PostgreSQL creado en Dokploy
- [ ] Redis creado en Dokploy
- [ ] Dominios apuntando a Contabo
- [ ] Resend API key obtenida

### Auth Service

- [ ] Repo en GitHub
- [ ] Dockerfile en raíz
- [ ] docker-entrypoint.sh ejecutable
- [ ] Variables de entorno configuradas
- [ ] Volumen `/app/keys` configurado
- [ ] Dominio configurado
- [ ] Deploy exitoso
- [ ] JWKS accesible

### Backend

- [ ] Dockerfile creado
- [ ] `jwks-rsa` en package.json
- [ ] Middleware implementado
- [ ] Variable AUTH_JWKS_URL configurada
- [ ] Deploy exitoso
- [ ] Prueba con token funciona

### Frontend

- [ ] Dockerfile con nginx
- [ ] Build args configurados
- [ ] Servicios auth/api implementados
- [ ] Deploy exitoso
- [ ] Login end-to-end funciona

---

## 🎯 Resultado

```
✅ Auth Service genera claves automáticamente
✅ Claves persisten entre deploys (volumen)
✅ JWKS distribuye claves vía HTTPS
✅ Backends obtienen claves automáticamente
✅ Sin archivos compartidos
✅ Sin configuración manual
✅ 100% funcional en Dokploy/Contabo
```

**Todo vía HTTP público. Arquitectura real de producción.**
