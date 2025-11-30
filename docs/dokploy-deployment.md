# Despliegue en Dokploy (Contabo)

## 🎯 Ventajas del JWKS en Dokploy

Con JWKS implementado, tus microservicios en Dokploy se configuran automáticamente:

```
✅ No copiar archivos public.pem manualmente
✅ Nuevos servicios se auto-configuran
✅ Rotación de claves sin downtime
✅ URL única para todos: https://auth.tudominio.com/.well-known/jwks.json
```

---

## 📋 Paso 1: Desplegar Auth Service

### En Dokploy

1. **Crear nuevo servicio**
   - Tipo: Docker
   - Nombre: `auth-service`
   - Puerto: `8080`

2. **Variables de entorno**

```bash
# Server
SERVER_PORT=8080
ENVIRONMENT=production

# Database (usar DB de Dokploy)
DB_HOST=postgres
DB_PORT=5432
DB_USER=auth
DB_PASSWORD=<tu-password-seguro>
DB_NAME=authdb
DB_SSLMODE=require

# Redis (usar Redis de Dokploy)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=<tu-password-redis>

# JWT
JWT_PRIVATE_KEY_PATH=/keys/private.pem
JWT_PUBLIC_KEY_PATH=/keys/public.pem
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
```

3. **Volúmenes (para claves RSA)**

```
./keys:/keys:ro
```

4. **Dominio**
   - Configurar: `auth.tudominio.com`
   - SSL: Automático con Let's Encrypt

---

## 📋 Paso 2: Desplegar Backend (Node.js ejemplo)

### Dockerfile

```dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 4000

CMD ["node", "server.js"]
```

### Variables de entorno en Dokploy

```bash
PORT=4000
NODE_ENV=production

# JWKS URL (¡Solo esto!)
AUTH_JWKS_URL=https://auth.tudominio.com/.well-known/jwks.json

# Tu base de datos
DATABASE_URL=postgresql://...
```

### Código del backend

```javascript
// middleware/auth.js
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

// Cliente JWKS - obtiene claves automáticamente
const client = jwksClient({
  jwksUri: process.env.AUTH_JWKS_URL,
  cache: true,
  cacheMaxAge: 600000, // 10 minutos
  rateLimit: true,
  jwksRequestsPerMinute: 10
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = {
      id: decoded.uid,
      email: decoded.email,
      roles: decoded.roles || []
    };
    
    next();
  });
}

module.exports = { authenticate };
```

### package.json

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "jwks-rsa": "^3.1.0"
  }
}
```

---

## 📋 Paso 3: Desplegar Frontend (React ejemplo)

### Variables de entorno en Dokploy

```bash
REACT_APP_AUTH_URL=https://auth.tudominio.com
REACT_APP_API_URL=https://api.tudominio.com
```

### Código del frontend

```javascript
// src/services/auth.js
const AUTH_API = process.env.REACT_APP_AUTH_URL;
const APP_ID = '00000000-0000-0000-0000-000000000000';

export async function login(email, password) {
  const response = await fetch(`${AUTH_API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, app_id: APP_ID })
  });
  
  const data = await response.json();
  
  localStorage.setItem('access_token', data.tokens.access_token);
  localStorage.setItem('refresh_token', data.tokens.refresh_token);
  
  return data;
}

// src/services/api.js
const API_URL = process.env.REACT_APP_API_URL;

export async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (response.status === 401) {
    // Token expirado, redirigir a login
    window.location.href = '/login';
  }
  
  return response.json();
}
```

---

## 🔧 Configuración de Servicios en Dokploy

### Estructura recomendada

```
Proyecto: mi-app
├── auth-service (puerto 8080)
│   └── Dominio: auth.tudominio.com
├── backend-api (puerto 4000)
│   └── Dominio: api.tudominio.com
├── frontend (puerto 80)
│   └── Dominio: app.tudominio.com
├── postgres (interno)
└── redis (interno)
```

### Red interna

Todos los servicios en Dokploy están en la misma red Docker, pueden comunicarse por nombre:

```javascript
// Backend puede llamar directamente (interno)
const response = await fetch('http://auth-service:8080/.well-known/jwks.json');

// Frontend usa dominio público (externo)
const response = await fetch('https://auth.tudominio.com/api/v1/auth/login');
```

---

## 🧪 Probar JWKS

### 1. Verificar endpoint JWKS

```bash
curl https://auth.tudominio.com/.well-known/jwks.json
```

**Respuesta esperada:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-12-01",
      "alg": "RS256",
      "n": "xGOr-H7A...",
      "e": "AQAB"
    }
  ]
}
```

### 2. Probar login

```bash
curl -X POST https://auth.tudominio.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "Admin123!",
    "app_id": "00000000-0000-0000-0000-000000000000"
  }'
```

### 3. Probar backend con token

```bash
TOKEN="<access_token_del_login>"

curl https://api.tudominio.com/api/products \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🔄 Agregar Nuevo Microservicio

### Antes (sin JWKS)

```bash
1. Copiar public.pem al nuevo servicio ❌
2. Configurar path del archivo ❌
3. Montar volumen en Docker ❌
4. Reiniciar servicio ❌
```

### Ahora (con JWKS)

```bash
1. Agregar variable: AUTH_JWKS_URL=https://auth.tudominio.com/.well-known/jwks.json ✅
2. Listo! ✅
```

**Ejemplo Python (FastAPI):**

```python
# main.py
import os
from fastapi import FastAPI, Depends, HTTPException
from jose import jwt, JWTError
import requests

app = FastAPI()

JWKS_URL = os.getenv('AUTH_JWKS_URL')

# Cachear JWKS
jwks_cache = None
jwks_cache_time = 0

def get_jwks():
    global jwks_cache, jwks_cache_time
    import time
    
    # Cache por 10 minutos
    if jwks_cache and (time.time() - jwks_cache_time) < 600:
        return jwks_cache
    
    response = requests.get(JWKS_URL)
    jwks_cache = response.json()
    jwks_cache_time = time.time()
    return jwks_cache

def verify_token(token: str):
    try:
        jwks = get_jwks()
        header = jwt.get_unverified_header(token)
        
        # Encontrar clave correcta
        key = next((k for k in jwks['keys'] if k['kid'] == header['kid']), None)
        if not key:
            raise HTTPException(401, "Invalid token")
        
        # Validar token
        payload = jwt.decode(token, key, algorithms=['RS256'])
        return payload
    except JWTError:
        raise HTTPException(401, "Invalid token")

@app.get("/products")
def get_products(token: str = Depends(verify_token)):
    return {"user_id": token['uid'], "products": []}
```

**Dockerfile:**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4000"]
```

**requirements.txt:**

```
fastapi
uvicorn
python-jose[cryptography]
requests
```

**En Dokploy:**

```bash
AUTH_JWKS_URL=https://auth.tudominio.com/.well-known/jwks.json
```

---

## 🔒 Rotación de Claves (Futuro)

Cuando necesites rotar claves:

```bash
# 1. Generar nueva clave
openssl genrsa -out keys/private-new.pem 4096
openssl rsa -in keys/private-new.pem -pubout -out keys/public-new.pem

# 2. Actualizar Auth Service para publicar AMBAS claves en JWKS
# (modificar código para incluir múltiples keys)

# 3. Esperar 15 minutos (expiración de tokens)

# 4. Eliminar clave vieja del JWKS

# ✅ Sin downtime, sin actualizar backends
```

---

## 📊 Monitoreo

### Logs en Dokploy

```bash
# Ver logs del auth-service
dokploy logs auth-service

# Ver requests al JWKS
dokploy logs auth-service | grep "/.well-known/jwks.json"
```

### Métricas importantes

- Requests a `/health` → Uptime
- Requests a `/.well-known/jwks.json` → Backends obteniendo claves
- Requests a `/api/v1/auth/login` → Logins
- Errores 401 → Tokens inválidos

---

## ✅ Checklist de Despliegue

### Auth Service

- [ ] Variables de entorno configuradas
- [ ] Claves RSA generadas y montadas
- [ ] Dominio configurado (auth.tudominio.com)
- [ ] SSL activo
- [ ] Migraciones ejecutadas
- [ ] Usuario admin creado
- [ ] JWKS endpoint accesible públicamente

### Backend Services

- [ ] Variable AUTH_JWKS_URL configurada
- [ ] Librería JWKS instalada (jwks-rsa, python-jose, etc)
- [ ] Middleware de autenticación implementado
- [ ] Dominio configurado
- [ ] SSL activo

### Frontend

- [ ] Variables REACT_APP_AUTH_URL y REACT_APP_API_URL configuradas
- [ ] Servicio de auth implementado
- [ ] Interceptor de tokens implementado
- [ ] Manejo de errores 401
- [ ] Dominio configurado
- [ ] SSL activo

---

## 🆘 Troubleshooting

### Error: "JWKS endpoint not found"

```bash
# Verificar que el endpoint responde
curl https://auth.tudominio.com/.well-known/jwks.json

# Si no responde, verificar logs
dokploy logs auth-service
```

### Error: "Invalid token signature"

```bash
# Verificar que backend usa la URL correcta
echo $AUTH_JWKS_URL

# Limpiar cache de JWKS en backend
# (reiniciar servicio)
```

### Error: "CORS policy"

```bash
# Agregar dominio del frontend a CORS_ALLOWED_ORIGINS
CORS_ALLOWED_ORIGINS=https://app.tudominio.com,https://admin.tudominio.com
```

---

## 🚀 Resultado Final

```
Frontend (app.tudominio.com)
    ↓ Login
Auth Service (auth.tudominio.com)
    ↓ Token
Frontend guarda token
    ↓ Request con token
Backend (api.tudominio.com)
    ↓ Valida token con JWKS
    ↓ (obtiene clave de auth.tudominio.com/.well-known/jwks.json)
    ✅ Request autorizado
```

**Todo automático, sin copiar archivos, sin configuración manual!**
