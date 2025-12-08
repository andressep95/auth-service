# Guía de Integración - Auth Service

## 🎯 ¿Qué es este servicio?

Este es un **Identity Provider (IdP)** centralizado que gestiona:

- Autenticación (quién eres)
- Autorización (qué puedes hacer)
- Sesiones de usuario
- Roles y permisos

## 🏗️ Arquitectura de Integración

```
┌─────────────────────────────────────────────────────────────┐
│                         FRONTEND                            │
│                    (React/Vue/Angular)                      │
│                                                             │
│  • Formularios de login/registro                           │
│  • Guarda tokens en localStorage/cookies                   │
│  • Envía token en cada request                             │
│  • Redirige a login si token inválido                      │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ 1. POST /auth/login
                   │    → Recibe access_token + refresh_token
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                      AUTH SERVICE                           │
│                    (Este microservicio)                     │
│                                                             │
│  • Valida credenciales                                      │
│  • Genera JWT tokens                                        │
│  • Gestiona roles y permisos                                │
│  • Endpoint público: /auth/*                                │
│  • Endpoint protegido: /users/me, /admin/*                  │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ 2. Frontend hace requests a backend
                   │    con: Authorization: Bearer <token>
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND SERVICES                         │
│              (API de productos, pedidos, etc.)              │
│                                                             │
│  • Reciben token en header Authorization                    │
│  • Validan token con clave pública del Auth Service        │
│  • Extraen user_id, roles del token                         │
│  • Autorizan según roles/permisos                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Flujos de Integración

### 1️⃣ Flujo de Login (Frontend → Auth Service)

```javascript
// FRONTEND: Login del usuario
async function login(email, password) {
  const response = await fetch("http://auth-service:8080/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email,
      password: password,
      app_id: "7057e69d-818b-45db-b39b-9d1c84aca142", // Tu app ID
    }),
  });

  const data = await response.json();

  // Guardar tokens
  localStorage.setItem("access_token", data.tokens.access_token);
  localStorage.setItem("refresh_token", data.tokens.refresh_token);
  localStorage.setItem("user", JSON.stringify(data.user));

  return data;
}
```

### 2️⃣ Flujo de Request Protegido (Frontend → Backend)

```javascript
// FRONTEND: Request a tu backend con el token
async function getProducts() {
  const token = localStorage.getItem("access_token");

  const response = await fetch("http://backend-api:3000/api/products", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  return response.json();
}
```

### 3️⃣ Validación de Token (Backend recibe request)

```javascript
// BACKEND: Middleware para validar token
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Obtener clave pública del Auth Service (una sola vez al iniciar)
const publicKey = fs.readFileSync('./auth-service-public.pem');

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);

  try {
    // Validar token con la clave pública
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

    // Token válido, extraer información
    req.user = {
      id: decoded.uid,
      email: decoded.email,
      roles: decoded.roles || [],
      permissions: decoded.permissions || []
    };

    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Usar en tus rutas
app.get('/api/products', authMiddleware, (req, res) => {
  // req.user contiene la info del usuario
  console.log('User ID:', req.user.id);
  console.log('Roles:', req.user.roles);

  // Tu lógica de negocio
  res.json({ products: [...] });
});
```

### 4️⃣ Autorización por Roles (Backend)

```javascript
// BACKEND: Middleware para verificar roles
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const userRoles = req.user.roles || [];

    const hasRole = allowedRoles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: "Forbidden",
        required_roles: allowedRoles,
      });
    }

    next();
  };
}

// Usar en rutas protegidas
app.delete(
  "/api/products/:id",
  authMiddleware, // Primero valida token
  requireRole("admin"), // Luego verifica rol
  (req, res) => {
    // Solo admins llegan aquí
    res.json({ message: "Product deleted" });
  }
);
```

### 5️⃣ Refresh Token (Frontend)

```javascript
// FRONTEND: Renovar access token cuando expira
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem("refresh_token");

  const response = await fetch("http://auth-service:8080/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  const data = await response.json();

  // Actualizar tokens
  localStorage.setItem("access_token", data.access_token);
  localStorage.setItem("refresh_token", data.refresh_token);

  return data.access_token;
}

// Interceptor para renovar automáticamente
async function fetchWithAuth(url, options = {}) {
  let token = localStorage.getItem("access_token");

  options.headers = {
    ...options.headers,
    Authorization: `Bearer ${token}`,
  };

  let response = await fetch(url, options);

  // Si token expiró, renovar y reintentar
  if (response.status === 401) {
    token = await refreshAccessToken();
    options.headers.Authorization = `Bearer ${token}`;
    response = await fetch(url, options);
  }

  return response;
}
```

---

## 🔑 Obtener la Clave Pública

Tus backends necesitan la clave pública para validar tokens.

### Opción 1: Copiar archivo (Desarrollo)

```bash
# Desde el auth-service
cp keys/public.pem /path/to/backend/auth-service-public.pem
```

### Opción 2: Endpoint JWKS (Producción - Futuro)

```javascript
// Backend obtiene clave pública vía HTTP
const response = await fetch("http://auth-service:8080/.well-known/jwks.json");
const jwks = await response.json();
// Usar librería como node-jwks-rsa
```

---

## 📋 Checklist de Integración

### Frontend

- [ ] Implementar formulario de login
- [ ] Guardar tokens en localStorage/cookies
- [ ] Enviar token en header `Authorization: Bearer <token>`
- [ ] Implementar refresh token automático
- [ ] Manejar errores 401 (redirigir a login)
- [ ] Manejar errores 403 (sin permisos)
- [ ] Implementar logout (limpiar tokens)

### Backend

- [ ] Obtener clave pública del Auth Service
- [ ] Implementar middleware de autenticación
- [ ] Validar tokens con RS256
- [ ] Extraer user_id, roles del token
- [ ] Implementar middleware de autorización por roles
- [ ] Manejar tokens expirados
- [ ] NO validar tokens contra base de datos (stateless)

### Auth Service

- [ ] Configurar CORS para tu frontend
- [ ] Registrar tu aplicación (app_id)
- [ ] Crear roles necesarios
- [ ] Asignar permisos a roles
- [ ] Configurar email service (opcional)

---

## 🌐 Configuración de Dominios

### Desarrollo Local

```
Frontend:     http://localhost:3000
Auth Service: http://localhost:8080
Backend API:  http://localhost:4000
```

### Producción

```
Frontend:     https://app.tudominio.com
Auth Service: https://auth.tudominio.com
Backend API:  https://api.tudominio.com
```

**CORS en Auth Service (.env):**

```bash
CORS_ALLOWED_ORIGINS=https://app.tudominio.com,http://localhost:3000
```

---

## 🔐 Estructura del JWT Token

Cuando validas el token en tu backend, obtienes:

```json
{
  "iss": "auth-service",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "token-uuid",
  "uid": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "permissions": ["users:read:own", "users:update:own"],
  "app_id": "7057e69d-818b-45db-b39b-9d1c84aca142",
  "type": "access"
}
```

**Campos importantes:**

- `uid`: ID del usuario (úsalo como foreign key)
- `email`: Email del usuario
- `roles`: Array de roles
- `permissions`: Array de permisos (opcional)
- `app_id`: ID de tu aplicación

---

## 🎨 Ejemplo Completo: React + Node.js

### Frontend (React)

```jsx
// src/services/auth.js
const AUTH_API = "http://localhost:8080/api/v1";
const APP_ID = "7057e69d-818b-45db-b39b-9d1c84aca142";

export const authService = {
  async login(email, password) {
    const response = await fetch(`${AUTH_API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, app_id: APP_ID }),
    });

    if (!response.ok) throw new Error("Login failed");

    const data = await response.json();
    localStorage.setItem("access_token", data.tokens.access_token);
    localStorage.setItem("refresh_token", data.tokens.refresh_token);

    return data;
  },

  logout() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },

  getToken() {
    return localStorage.getItem("access_token");
  },
};

// src/services/api.js
import { authService } from "./auth";

export async function apiRequest(url, options = {}) {
  const token = authService.getToken();

  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${token}`,
    },
  });

  if (response.status === 401) {
    authService.logout();
    window.location.href = "/login";
  }

  return response.json();
}
```

### Backend (Node.js/Express)

```javascript
// middleware/auth.js
const jwt = require("jsonwebtoken");
const fs = require("fs");

const publicKey = fs.readFileSync("./auth-service-public.pem");

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "No token" });
  }

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
}

function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.some((role) => req.user.roles?.includes(role))) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

module.exports = { authenticate, authorize };

// routes/products.js
const express = require("express");
const { authenticate, authorize } = require("../middleware/auth");

const router = express.Router();

router.get("/", authenticate, (req, res) => {
  // Todos los usuarios autenticados
  res.json({ products: [] });
});

router.post("/", authenticate, authorize("admin"), (req, res) => {
  // Solo admins
  res.json({ message: "Product created" });
});

module.exports = router;
```

---

## 🚀 Despliegue

### Docker Compose (Todos los servicios)

```yaml
version: "3.8"

services:
  auth-service:
    build: ./auth-service
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://auth:auth@postgres:5432/authdb
      - REDIS_URL=redis://redis:6379
      - CORS_ALLOWED_ORIGINS=http://localhost:3000,http://frontend:80
    volumes:
      - ./keys:/keys:ro

  backend-api:
    build: ./backend-api
    ports:
      - "4000:4000"
    environment:
      - AUTH_PUBLIC_KEY_PATH=/keys/public.pem
    volumes:
      - ./keys/public.pem:/keys/public.pem:ro
    depends_on:
      - auth-service

  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    environment:
      - REACT_APP_AUTH_URL=http://localhost:8080
      - REACT_APP_API_URL=http://localhost:4000
    depends_on:
      - auth-service
      - backend-api

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: auth
      POSTGRES_PASSWORD: auth
      POSTGRES_DB: authdb
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

---

## ❓ FAQ

### ¿El backend debe consultar el Auth Service en cada request?

**NO.** El backend solo valida el token JWT con la clave pública. Es stateless y rápido.

### ¿Dónde guardo el user_id en mi base de datos?

Usa el `uid` del token como foreign key:

```sql
CREATE TABLE orders (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,  -- Este es el uid del token
  total DECIMAL,
  created_at TIMESTAMP
);
```

### ¿Cómo sincronizo usuarios entre servicios?

**Opción 1:** Crear usuario en tu DB cuando haces el primer request

```javascript
app.post("/api/orders", authenticate, async (req, res) => {
  // Asegurar que el usuario existe en tu DB
  await ensureUserExists(req.user.id, req.user.email);

  // Crear orden
  const order = await createOrder(req.user.id, req.body);
  res.json(order);
});
```

**Opción 2:** Event-driven (futuro)

- Auth Service publica evento "UserCreated"
- Tus servicios escuchan y crean usuario local

### ¿Qué pasa si cambio la clave RSA?

Todos los tokens existentes se invalidan. Planifica rotación de claves:

1. Genera nueva clave
2. Publica ambas claves públicas (vieja + nueva)
3. Backends validan con ambas
4. Después de 15 min (expiración de tokens), elimina clave vieja

---

## 📚 Recursos

- [JWT.io](https://jwt.io) - Debugger de tokens
- [OpenAPI Spec](./openapi.yaml) - Documentación completa de la API
- [CLAUDE.md](../CLAUDE.md) - Documentación técnica del Auth Service

---

**¿Dudas?** Revisa los ejemplos en `docs/examples/` o consulta el CLAUDE.md
