# Scripts de Automatización

## 📋 Script Disponible

### `full-setup.sh` - Setup Completo ⭐

**Propósito:** Inicializa todo el sistema desde cero con un solo comando.

**Uso:**

```bash
# Opción 1: Con credenciales por defecto
make quickstart

# Opción 2: Con credenciales personalizadas (interactivo)
make quickstart-custom

# Opción 3: Ejecutar script directamente
./scripts/full-setup.sh
```

**Qué hace:**

1. ✅ Verifica dependencias (Docker, Docker Compose, OpenSSL)
2. ✅ Limpia recursos previos
3. ✅ Genera claves RSA para JWT
4. ✅ Inicia servicios Docker (PostgreSQL, Redis, App)
5. ✅ Espera a que PostgreSQL esté listo
6. ✅ Ejecuta todas las migraciones
7. ✅ Verifica que el código compile
8. ✅ Espera a que la aplicación esté lista
9. ✅ Crea usuario administrador
10. ✅ Guarda credenciales en `.admin-credentials`
11. ✅ Muestra resumen del sistema

**Cuándo usar:**

- Primera vez que configuras el proyecto
- Después de clonar el repositorio
- Para resetear el sistema completamente

---

## 🚀 Flujo Recomendado

### Primera Vez (Setup Inicial)

```bash
# Opción 1: Automático con credenciales por defecto
make quickstart

# Opción 2: Interactivo con credenciales personalizadas
make quickstart-custom
```

### Crear Admin Adicional

```bash
# Usar el endpoint de la API (requiere ser admin)
curl -X POST "http://localhost:8080/api/v1/admin/users/{userId}/roles/{adminRoleId}" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# O directamente en la base de datos
docker-compose exec postgres psql -U auth -d authdb
INSERT INTO user_roles (user_id, role_id, assigned_at)
VALUES ('user-uuid', '20000000-0000-0000-0000-000000000002', NOW());
```

### Generar Solo Claves RSA

```bash
# Si solo necesitas regenerar las claves
make keys

# O manualmente:
mkdir -p keys
openssl genrsa -out keys/private.pem 4096
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

---

## 📝 Notas

### Archivo `.admin-credentials`

Ambos scripts crean este archivo automáticamente:

```bash
# Credenciales del administrador
# ¡MANTÉN ESTE ARCHIVO SEGURO!
ADMIN_EMAIL="admin@test.com"
ADMIN_PASSWORD="Admin123!"
API_URL="http://localhost:8080"
APP_ID="7057e69d-818b-45db-b39b-9d1c84aca142"
```

**Uso:**

```bash
# Cargar credenciales en tu terminal
source .admin-credentials

# Usar las variables
curl -X POST $API_URL/api/v1/auth/login \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"app_id\":\"$APP_ID\"}"
```

### Seguridad

- ✅ `.admin-credentials` tiene permisos `600` (solo tú puedes leerlo)
- ✅ Está en `.gitignore` (no se commitea)
- ✅ Las contraseñas no se muestran en logs (aparecen como `********`)

---

## 🔧 Troubleshooting

### "Docker no está instalado"

```bash
# macOS
brew install docker docker-compose

# Linux
sudo apt-get install docker.io docker-compose
```

### "Error compilando aplicación"

```bash
# Verificar versión de Go
go version  # Debe ser 1.24+

# Limpiar y recompilar
go clean
go mod tidy
go build -o bin/auth-service cmd/main.go
```

### "Timeout esperando PostgreSQL"

```bash
# Ver logs de PostgreSQL
docker-compose logs postgres

# Reiniciar PostgreSQL
docker-compose restart postgres
```

### "Usuario ya existe"

```bash
# El script detecta esto automáticamente y usa el usuario existente
# Si quieres empezar de cero:
make db-reset  # ⚠️ Esto borra todos los datos
```

---

## 📚 Más Información

- Ver `CLAUDE.md` para documentación completa
- Ver `docs/architecture.md` para arquitectura del sistema
- Ver `CHANGELOG.md` para historial de cambios
