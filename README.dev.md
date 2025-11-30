# Auth Service - Guía de Desarrollo

Microservicio de autenticación construido con Go, Fiber, PostgreSQL y Redis.

## 🚀 Inicio Rápido

### Prerrequisitos

- Go 1.23+
- Docker y Docker Compose
- Make (opcional, pero recomendado)

### Configuración Inicial

1. **Clonar el repositorio y entrar al directorio**
   ```bash
   cd auth-service
   ```

2. **Generar claves RSA para JWT**
   ```bash
   make keys
   ```

3. **Iniciar servicios con Docker**
   ```bash
   make docker-up
   ```

4. **Ejecutar migraciones**
   ```bash
   make migrate
   ```

5. **Compilar y ejecutar**
   ```bash
   make build
   make run
   ```

O simplemente usar:
```bash
make dev  # Genera keys + inicia Docker
```

## 📁 Estructura del Proyecto

```
auth-service/
├── cmd/
│   └── main.go                 # Punto de entrada de la aplicación
├── internal/
│   ├── config/                 # Configuración de la aplicación
│   ├── domain/                 # Entidades de dominio
│   │   ├── user.go
│   │   ├── session.go
│   │   ├── token.go
│   │   └── role.go
│   ├── repository/             # Interfaces de repositorios
│   │   └── postgres/           # Implementaciones PostgreSQL
│   ├── service/                # Lógica de negocio
│   │   ├── auth_service.go
│   │   └── user_service.go
│   └── handler/                # Handlers HTTP
│       ├── auth_handler.go
│       ├── user_handler.go
│       ├── routes.go
│       └── middleware/
│           ├── auth.go
│           ├── logger.go
│           ├── cors.go
│           └── recovery.go
├── pkg/                        # Paquetes reutilizables
│   ├── jwt/                    # Servicio de tokens JWT
│   ├── hash/                   # Hashing con Argon2
│   └── validator/              # Validación de requests
├── migrations/                 # Migraciones SQL
├── scripts/                    # Scripts de utilidad
└── keys/                       # Claves RSA (generadas)
```

## 🔧 Comandos Make Disponibles

```bash
make help         # Mostrar ayuda
make build        # Compilar la aplicación
make run          # Ejecutar la aplicación localmente
make test         # Ejecutar tests
make clean        # Limpiar archivos generados
make fmt          # Formatear código
make tidy         # Organizar dependencias

# Docker
make docker-up    # Iniciar servicios (PostgreSQL + Redis)
make docker-down  # Detener servicios
make docker-logs  # Ver logs
make docker-build # Construir imagen

# Desarrollo
make dev          # Configurar entorno completo
make keys         # Generar claves RSA
make migrate      # Ejecutar migraciones
```

## 🌐 Endpoints API

### Públicos

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |
| `POST` | `/api/v1/auth/register` | Registro de usuario |
| `POST` | `/api/v1/auth/login` | Login (retorna tokens) |
| `POST` | `/api/v1/auth/refresh` | Refresh token |
| `POST` | `/api/v1/auth/logout` | Logout |

### Protegidos (requieren Bearer token)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/v1/users/me` | Perfil del usuario actual |

## 📝 Ejemplos de Uso

### 1. Registrar un usuario

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### 2. Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "app_id": "00000000-0000-0000-0000-000000000000"
  }'
```

Respuesta:
```json
{
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "expires_at": "2024-01-01T00:15:00Z",
    "token_type": "Bearer"
  },
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

### 3. Acceder a ruta protegida

```bash
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Refresh token

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

### 5. Logout

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

## 🔐 Seguridad

- **Passwords**: Hasheados con Argon2id
- **Tokens**: JWT firmados con RS256 (RSA)
- **Refresh Tokens**: Almacenados hasheados con SHA-256
- **Session Management**: Redis para sesiones activas
- **Account Locking**: Bloqueo automático después de intentos fallidos
- **CORS**: Configurado para desarrollo

## 🗃️ Base de Datos

### PostgreSQL

Conectarse directamente:
```bash
docker exec -it auth-service-postgres-1 psql -U auth -d authdb
```

### Redis

Conectarse directamente:
```bash
docker exec -it auth-service-redis-1 redis-cli
```

## ⚙️ Variables de Entorno

Ver `.env` o `.env.example` para la configuración completa.

Principales variables:
- `SERVER_PORT`: Puerto del servidor (default: 8080)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: Configuración PostgreSQL
- `REDIS_HOST`, `REDIS_PORT`: Configuración Redis
- `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`: Rutas a las claves RSA
- `JWT_ACCESS_EXPIRY`, `JWT_REFRESH_EXPIRY`: Tiempos de expiración

## 🧪 Testing

```bash
# Ejecutar todos los tests
make test

# Ver cobertura
make coverage
```

## 📦 Deployment

### Con Docker Compose

```bash
docker-compose up -d
```

### Build de producción

```bash
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/auth-service cmd/main.go
```

## 🛠️ Desarrollo

### Agregar nuevas migraciones

1. Crear archivo en `migrations/` con numeración secuencial (ej: `002_add_mfa.sql`)
2. Ejecutar `make migrate`

### Agregar nuevos endpoints

1. Definir DTOs en `internal/service/`
2. Implementar lógica en el servicio correspondiente
3. Crear handler en `internal/handler/`
4. Registrar ruta en `internal/handler/routes.go`

## 🔍 Debugging

Ver logs de todos los servicios:
```bash
make docker-logs
```

Ver logs solo del auth-service:
```bash
docker-compose logs -f auth-service
```

## 📚 Recursos

- [Fiber Documentation](https://docs.gofiber.io/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/docs/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. Commit tus cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la licencia MIT.
