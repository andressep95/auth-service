#!/bin/bash

# Script para crear el primer usuario administrador
# Uso: ./scripts/create-first-admin.sh [email] [password] [first_name] [last_name]

set -e

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuración
API_URL="${API_URL:-http://localhost:8080}"
APP_ID="00000000-0000-0000-0000-000000000000"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  🔐 Creación de Primer Usuario Administrador              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Parámetros (usar argumentos o valores por defecto)
EMAIL="${1:-admin@test.com}"
PASSWORD="${2:-Admin123!}"
FIRST_NAME="${3:-Admin}"
LAST_NAME="${4:-User}"

echo -e "${YELLOW}📋 Datos del usuario:${NC}"
echo "   Email:      $EMAIL"
echo "   Password:   ********"
echo "   Nombre:     $FIRST_NAME $LAST_NAME"
echo ""

# Paso 1: Registrar usuario
echo -e "${BLUE}🔄 Paso 1/3: Registrando usuario...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"password\": \"$PASSWORD\",
    \"first_name\": \"$FIRST_NAME\",
    \"last_name\": \"$LAST_NAME\"
  }")

# Verificar si el registro fue exitoso
if echo "$REGISTER_RESPONSE" | grep -q '"id"'; then
    USER_ID=$(echo "$REGISTER_RESPONSE" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
    echo -e "${GREEN}✓ Usuario registrado exitosamente${NC}"
    echo "   User ID: $USER_ID"
elif echo "$REGISTER_RESPONSE" | grep -q "already exists"; then
    echo -e "${YELLOW}⚠️  Usuario ya existe, obteniendo ID...${NC}"
    # Obtener el ID del usuario existente desde la base de datos
    USER_ID=$(docker-compose exec -T postgres psql -U auth -d authdb -t -c "SELECT id FROM users WHERE email = '$EMAIL';" | tr -d ' \n')
    if [ -z "$USER_ID" ]; then
        echo -e "${RED}❌ Error: No se pudo obtener el ID del usuario${NC}"
        exit 1
    fi
    echo "   User ID: $USER_ID"
else
    echo -e "${RED}❌ Error al registrar usuario:${NC}"
    echo "$REGISTER_RESPONSE"
    exit 1
fi

echo ""

# Paso 2: Promover a admin
echo -e "${BLUE}🔄 Paso 2/3: Promoviendo a administrador...${NC}"
ADMIN_ROLE_ID="20000000-0000-0000-0000-000000000002"

PROMO_RESULT=$(docker-compose exec -T postgres psql -U auth -d authdb -c \
  "INSERT INTO user_roles (user_id, role_id, assigned_at)
   VALUES ('$USER_ID', '$ADMIN_ROLE_ID', NOW())
   ON CONFLICT (user_id, role_id) DO NOTHING;" 2>&1)

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Rol admin asignado exitosamente${NC}"
else
    echo -e "${RED}❌ Error al asignar rol admin${NC}"
    exit 1
fi

echo ""

# Paso 3: Verificar y hacer login de prueba
echo -e "${BLUE}🔄 Paso 3/3: Verificando credenciales...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"password\": \"$PASSWORD\",
    \"app_id\": \"$APP_ID\"
  }")

if echo "$LOGIN_RESPONSE" | grep -q '"access_token"'; then
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    echo -e "${GREEN}✓ Login exitoso${NC}"
    echo ""

    # Verificar roles
    echo -e "${BLUE}🔍 Verificando roles asignados...${NC}"
    ROLES_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/users/me/roles" \
      -H "Authorization: Bearer $ACCESS_TOKEN")

    if echo "$ROLES_RESPONSE" | grep -q '"admin"'; then
        echo -e "${GREEN}✓ Rol admin confirmado${NC}"
    fi

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ¡ADMINISTRADOR CREADO EXITOSAMENTE!                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}📝 Credenciales:${NC}"
    echo "   Email:    $EMAIL"
    echo "   Password: $PASSWORD"
    echo ""
    echo -e "${YELLOW}🔑 Access Token (válido por 15 min):${NC}"
    echo "   ${ACCESS_TOKEN:0:50}..."
    echo ""
    echo -e "${BLUE}💡 Guarda este token para pruebas:${NC}"
    echo "   export ADMIN_TOKEN=\"$ACCESS_TOKEN\""
    echo ""
    echo -e "${BLUE}🧪 Prueba los endpoints de admin:${NC}"
    echo "   curl -X GET \"$API_URL/api/v1/admin/roles?app_id=$APP_ID\" \\"
    echo "     -H \"Authorization: Bearer \$ADMIN_TOKEN\""
    echo ""
else
    echo -e "${RED}❌ Error en login de verificación:${NC}"
    echo "$LOGIN_RESPONSE"
    exit 1
fi
