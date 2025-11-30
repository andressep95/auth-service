# Guía de Migraciones Automáticas

## 🎯 Cómo Funciona

Las migraciones se ejecutan **automáticamente** al iniciar el contenedor.

### Flujo de Inicio

```
1. Container inicia
2. docker-entrypoint.sh ejecuta
3. Genera claves RSA (si no existen)
4. Espera a que PostgreSQL esté listo
5. Ejecuta migraciones pendientes
6. Inicia aplicación Go
```

## 📋 Sistema de Migraciones

### Tabla de Control

Se crea automáticamente una tabla `schema_migrations`:

```sql
CREATE TABLE schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT NOW()
);
```

Esta tabla registra qué migraciones ya se aplicaron.

### Archivos de Migración

```
migrations/
├── 001_initial.sql
├── 002_seed_default_roles.sql
└── 003_add_email_verification.sql
```

**Convención de nombres:**
- `XXX_descripcion.sql`
- XXX = número secuencial (001, 002, 003...)
- Se ejecutan en orden alfabético

### Lógica de Ejecución

```bash
Para cada archivo .sql en /app/migrations:
  1. Extraer versión del nombre (ej: "001_initial")
  2. Verificar si existe en schema_migrations
  3. Si NO existe:
     - Ejecutar SQL
     - Registrar en schema_migrations
  4. Si SÍ existe:
     - Saltar (ya aplicada)
```

## 🚀 En Dokploy

### Primera Vez (Deploy Inicial)

```
1. Deploy del auth-service
2. Container inicia
3. Espera PostgreSQL
4. Ejecuta TODAS las migraciones (001, 002, 003)
5. Aplicación lista
```

**Logs esperados:**

```
🚀 Starting Auth Service initialization...

🔑 Checking RSA keys...
🔐 Generating RSA keys (4096 bits)...
✅ RSA keys generated

⏳ Waiting for PostgreSQL...
✅ PostgreSQL is ready

📊 Running database migrations...
   Creating migrations tracking table...
   Applying migration: 001_initial.sql
   ✅ Migration 001_initial.sql applied
   Applying migration: 002_seed_default_roles.sql
   ✅ Migration 002_seed_default_roles.sql applied
   Applying migration: 003_add_email_verification.sql
   ✅ Migration 003_add_email_verification.sql applied
✅ All migrations completed

🚀 Starting application...
```

### Redeploy (Actualización)

```
1. Redeploy del auth-service
2. Container inicia
3. Verifica migraciones
4. Solo ejecuta las NUEVAS (si hay)
5. Aplicación lista
```

**Logs esperados:**

```
🚀 Starting Auth Service initialization...

🔑 Checking RSA keys...
✅ RSA keys already exist

⏳ Waiting for PostgreSQL...
✅ PostgreSQL is ready

📊 Running database migrations...
   ⏭️  Migration 001_initial.sql already applied
   ⏭️  Migration 002_seed_default_roles.sql already applied
   ⏭️  Migration 003_add_email_verification.sql already applied
✅ All migrations completed

🚀 Starting application...
```

## ➕ Agregar Nueva Migración

### 1. Crear Archivo

```bash
# Crear nuevo archivo con número siguiente
touch migrations/004_add_user_preferences.sql
```

### 2. Escribir SQL

```sql
-- migrations/004_add_user_preferences.sql

-- Add preferences column to users
ALTER TABLE users ADD COLUMN preferences JSONB DEFAULT '{}';

-- Create index for JSONB queries
CREATE INDEX idx_users_preferences ON users USING GIN (preferences);

-- Add comment
COMMENT ON COLUMN users.preferences IS 'User preferences stored as JSON';
```

### 3. Commit y Push

```bash
git add migrations/004_add_user_preferences.sql
git commit -m "feat: Add user preferences column"
git push origin main
```

### 4. Redeploy en Dokploy

```
1. Dokploy detecta cambios
2. Rebuild del container
3. Al iniciar, ejecuta automáticamente 004_add_user_preferences.sql
4. Listo!
```

## 🔄 Rollback de Migraciones

### Opción 1: Migración Reversa (Recomendado)

Crear una nueva migración que deshace los cambios:

```sql
-- migrations/005_rollback_user_preferences.sql

-- Remove preferences column
ALTER TABLE users DROP COLUMN IF EXISTS preferences;

-- Drop index
DROP INDEX IF EXISTS idx_users_preferences;
```

### Opción 2: Manual (Emergencia)

```bash
# Conectar a PostgreSQL
psql -h <host> -U auth -d authdb

# Ejecutar SQL manualmente
ALTER TABLE users DROP COLUMN preferences;

# Eliminar registro de migración
DELETE FROM schema_migrations WHERE version = '004_add_user_preferences';
```

## 📝 Buenas Prácticas

### ✅ Hacer

1. **Migraciones Idempotentes**

```sql
-- Bueno: Usa IF NOT EXISTS
CREATE TABLE IF NOT EXISTS new_table (...);
ALTER TABLE users ADD COLUMN IF NOT EXISTS new_column VARCHAR(255);

-- Malo: Falla si ya existe
CREATE TABLE new_table (...);
ALTER TABLE users ADD COLUMN new_column VARCHAR(255);
```

2. **Migraciones Pequeñas**

```sql
-- Bueno: Una migración por feature
-- 004_add_user_avatar.sql
-- 005_add_user_bio.sql

-- Malo: Todo junto
-- 004_add_many_user_fields.sql
```

3. **Comentarios Descriptivos**

```sql
-- migrations/004_add_user_preferences.sql
-- Purpose: Add user preferences for theme, language, notifications
-- Author: @username
-- Date: 2024-12-01

ALTER TABLE users ADD COLUMN preferences JSONB DEFAULT '{}';
```

### ❌ Evitar

1. **Modificar Migraciones Aplicadas**

```bash
# ❌ NO HACER: Editar 001_initial.sql después de aplicada
# ✅ HACER: Crear 004_modify_users_table.sql
```

2. **Migraciones Destructivas sin Backup**

```sql
-- ❌ Peligroso sin backup
DROP TABLE users;

-- ✅ Mejor
-- Primero hacer backup manual
-- Luego crear migración
```

3. **Datos Hardcodeados**

```sql
-- ❌ Malo: IDs específicos
INSERT INTO users (id, email) VALUES ('123e4567...', 'admin@test.com');

-- ✅ Mejor: Usar gen_random_uuid()
INSERT INTO users (id, email) VALUES (gen_random_uuid(), 'admin@test.com');
```

## 🔍 Verificar Estado de Migraciones

### Desde Dokploy

Ver logs del container:

```bash
# En Dokploy → Auth Service → Logs
# Buscar: "Running database migrations"
```

### Desde PostgreSQL

```sql
-- Ver migraciones aplicadas
SELECT * FROM schema_migrations ORDER BY applied_at;

-- Resultado:
--  version              | applied_at
-- ----------------------+-------------------------
--  001_initial          | 2024-12-01 10:00:00
--  002_seed_default_roles | 2024-12-01 10:00:05
--  003_add_email_verification | 2024-12-01 10:00:10
```

## 🆘 Troubleshooting

### Error: "relation already exists"

**Causa:** Migración no es idempotente

**Solución:**

```sql
-- Cambiar de:
CREATE TABLE users (...);

-- A:
CREATE TABLE IF NOT EXISTS users (...);
```

### Error: "could not connect to server"

**Causa:** PostgreSQL no está listo

**Solución:** El script ya espera automáticamente. Si persiste:

1. Verificar variables DB_HOST, DB_USER, DB_PASSWORD
2. Verificar que PostgreSQL está corriendo en Dokploy
3. Ver logs de PostgreSQL

### Error: "permission denied"

**Causa:** Usuario DB sin permisos

**Solución:**

```sql
-- Conectar como superuser
GRANT ALL PRIVILEGES ON DATABASE authdb TO auth;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auth;
```

### Migración Quedó a Medias

**Síntoma:** Migración registrada pero SQL no completado

**Solución:**

```sql
-- 1. Verificar estado de la tabla
\d users

-- 2. Si falta algo, ejecutar manualmente
ALTER TABLE users ADD COLUMN missing_field VARCHAR(255);

-- 3. O eliminar registro y reintentar
DELETE FROM schema_migrations WHERE version = '004_problematic';
-- Luego redeploy
```

## 📊 Ejemplo Completo

### Migración: Agregar Sistema de Notificaciones

```sql
-- migrations/004_add_notifications.sql

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    read_at TIMESTAMPTZ
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read) WHERE read = FALSE;

-- Add notification preferences to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_preferences JSONB DEFAULT '{
    "email": true,
    "push": true,
    "in_app": true
}'::jsonb;

-- Comments
COMMENT ON TABLE notifications IS 'User notifications system';
COMMENT ON COLUMN users.notification_preferences IS 'User notification channel preferences';
```

**Commit:**

```bash
git add migrations/004_add_notifications.sql
git commit -m "feat: Add notifications system

- Create notifications table
- Add indexes for performance
- Add notification preferences to users"
git push origin main
```

**Deploy en Dokploy:**

```
1. Push a GitHub
2. Dokploy auto-rebuild
3. Container inicia
4. Migración 004 se ejecuta automáticamente
5. ✅ Sistema de notificaciones listo
```

---

## ✅ Resumen

```
✅ Migraciones automáticas al iniciar
✅ Solo ejecuta las nuevas
✅ Tracking en schema_migrations
✅ Idempotentes (IF NOT EXISTS)
✅ Orden secuencial garantizado
✅ Logs claros en Dokploy
✅ Sin intervención manual
```

**Workflow:**

```
1. Crear migrations/XXX_descripcion.sql
2. git commit && git push
3. Redeploy en Dokploy
4. ✅ Migración aplicada automáticamente
```
