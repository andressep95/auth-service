#!/bin/bash

# Script de configuración completa automatizada
# Inicializa todo el sistema con un solo comando

set -e

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuración por defecto
DEFAULT_EMAIL="bodyweightforce@gmail.com"
DEFAULT_PASSWORD="admin123."
DEFAULT_FIRST_NAME="Admin"
DEFAULT_LAST_NAME="User"
API_URL="http://localhost:8080"
APP_ID="7057e69d-818b-45db-b39b-9d1c84aca142"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  🚀 SETUP COMPLETO AUTOMATIZADO - Auth Service            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Función para verificar dependencias
check_dependencies() {
    echo -e "${BLUE}🔍 Verificando dependencias...${NC}"
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker no está instalado${NC}"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ Docker Compose no está instalado${NC}"
        exit 1
    fi
    
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}❌ OpenSSL no está instalado${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Todas las dependencias están disponibles${NC}"
}

# Función para limpiar recursos previos
cleanup_previous() {
    echo -e "${YELLOW}🧹 Limpiando recursos previos...${NC}"
    docker-compose down --volumes --remove-orphans 2>/dev/null || true
    echo -e "${GREEN}✓ Limpieza completa${NC}"
}

# Función para generar claves
generate_keys() {
    echo -e "${BLUE}🔑 Generando claves RSA...${NC}"
    
    KEYS_DIR="./keys"
    mkdir -p "$KEYS_DIR"
    
    if ! openssl genrsa -out "$KEYS_DIR/private.pem" 4096 2>/dev/null; then
        echo -e "${RED}❌ Error generando clave privada${NC}"
        exit 1
    fi
    
    if ! openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem" 2>/dev/null; then
        echo -e "${RED}❌ Error generando clave pública${NC}"
        exit 1
    fi
    
    chmod 600 "$KEYS_DIR/private.pem"
    chmod 644 "$KEYS_DIR/public.pem"
    
    echo -e "${GREEN}✓ Claves RSA generadas exitosamente${NC}"
}

# Función para iniciar servicios
start_services() {
    echo -e "${BLUE}🐳 Iniciando servicios Docker...${NC}"
    
    # Reconstruir la imagen para incluir cambios de código
    if ! docker-compose up -d --build; then
        echo -e "${RED}❌ Error iniciando servicios Docker${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Servicios Docker iniciados${NC}"
}

# Función para esperar PostgreSQL
wait_for_postgres() {
    echo -e "${BLUE}⏳ Esperando a PostgreSQL...${NC}"
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T postgres pg_isready -U auth -d authdb &>/dev/null; then
            echo -e "${GREEN}✓ PostgreSQL está listo${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}❌ Timeout esperando PostgreSQL${NC}"
    exit 1
}

# NOTA: Las migraciones se ejecutan automáticamente en docker-entrypoint.sh
# No es necesario ejecutarlas manualmente aquí para evitar duplicación
# El contenedor de auth-service ejecuta docker-entrypoint.sh al iniciar,
# que verifica la tabla schema_migrations y aplica migraciones pendientes


# Función para verificar que el código compila
verify_build() {
    echo -e "${BLUE}🔨 Verificando que el código compila...${NC}"
    
    go mod tidy
    
    if ! go build -o /tmp/auth-service-test cmd/main.go; then
        echo -e "${RED}❌ Error compilando aplicación${NC}"
        exit 1
    fi
    
    rm -f /tmp/auth-service-test
    echo -e "${GREEN}✓ Código compila correctamente${NC}"
}

# Función para esperar que la aplicación esté lista
wait_for_app() {
    echo -e "${BLUE}🚀 Esperando a que la aplicación esté lista...${NC}"
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$API_URL/health" &>/dev/null; then
            echo -e "${GREEN}✓ Aplicación está lista${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}❌ Timeout esperando aplicación${NC}"
    echo -e "${YELLOW}💡 Verificando logs del container...${NC}"
    docker-compose logs auth-service
    exit 1
}

# Función para crear usuario admin
create_admin_user() {
    local email="${1:-$DEFAULT_EMAIL}"
    local password="${2:-$DEFAULT_PASSWORD}"
    local first_name="${3:-$DEFAULT_FIRST_NAME}"
    local last_name="${4:-$DEFAULT_LAST_NAME}"
    
    echo -e "${BLUE}👤 Creando usuario administrador...${NC}"
    echo "   Email: $email"
    echo "   Nombre: $first_name $last_name"
    
    # Registrar usuario (con app_id y tenant_id del tenant "public")
    local public_tenant_id="00000000-0000-0000-0000-000000000001"
    local register_response
    register_response=$(curl -s -X POST "$API_URL/api/v1/auth/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"app_id\": \"$APP_ID\",
            \"tenant_id\": \"$public_tenant_id\",
            \"email\": \"$email\",
            \"password\": \"$password\",
            \"first_name\": \"$first_name\",
            \"last_name\": \"$last_name\"
        }")
    
    local user_id
    if echo "$register_response" | grep -q '"id"'; then
        user_id=$(echo "$register_response" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
        echo -e "${GREEN}✓ Usuario registrado${NC}"
    elif echo "$register_response" | grep -q "already exists"; then
        user_id=$(docker-compose exec -T postgres psql -U auth -d authdb -t -c \
            "SELECT id FROM users WHERE app_id = '$APP_ID' AND tenant_id = '$public_tenant_id' AND email = '$email';" | tr -d ' \n')
        echo -e "${YELLOW}⚠️  Usuario ya existe${NC}"
    else
        echo -e "${RED}❌ Error registrando usuario: $register_response${NC}"
        return 1
    fi
    
    # Promover a admin
    local super_admin_role_id="10000000-0000-0000-0000-000000000001"
    if docker-compose exec -T postgres psql -U auth -d authdb -c \
        "INSERT INTO user_roles (user_id, role_id, assigned_at)
         VALUES ('$user_id', '$super_admin_role_id', NOW())
         ON CONFLICT (user_id, role_id) DO NOTHING;" &>/dev/null; then
        echo -e "${GREEN}✓ Rol super_admin asignado${NC}"
    else
        echo -e "${RED}❌ Error asignando rol super_admin${NC}"
        return 1
    fi
    
    # Verificar login
    local login_response
    login_response=$(curl -s -X POST "$API_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"$email\",
            \"password\": \"$password\",
            \"app_id\": \"$APP_ID\"
        }")
    
    if echo "$login_response" | grep -q '"access_token"'; then
        echo -e "${GREEN}✓ Credenciales verificadas${NC}"
        
        # Guardar credenciales de forma segura
        cat > .admin-credentials << EOF
# Credenciales del administrador
# ¡MANTÉN ESTE ARCHIVO SEGURO!
ADMIN_EMAIL="$email"
ADMIN_PASSWORD="$password"
API_URL="$API_URL"
APP_ID="$APP_ID"
EOF
        chmod 600 .admin-credentials
        
        return 0
    else
        echo -e "${RED}❌ Error verificando credenciales${NC}"
        echo -e "${YELLOW}Respuesta del login:${NC}"
        echo "$login_response"
        echo ""
        echo -e "${YELLOW}💡 Verificando si el usuario existe en la base de datos...${NC}"
        docker-compose exec -T postgres psql -U auth -d authdb -c "SELECT email, status, tenant_id FROM users WHERE app_id = '$APP_ID' AND email = '$email';"
        return 1
    fi
}

# Función para mostrar resumen final
show_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ¡SISTEMA COMPLETAMENTE CONFIGURADO!                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}🎯 SISTEMA LISTO PARA USAR:${NC}"
    echo ""
    echo -e "${BLUE}📍 Endpoints:${NC}"
    echo "   • API:    $API_URL/api/v1"
    echo "   • Health: $API_URL/health"
    echo "   • Docs:   $API_URL/docs"
    echo ""
    echo -e "${BLUE}🗄️  Servicios:${NC}"
    echo "   • PostgreSQL: localhost:5432"
    echo "   • Redis:      localhost:6379"
    echo "   • Auth API:   localhost:8080"
    echo ""
    echo -e "${BLUE}👤 Administrador:${NC}"
    echo "   • Email:    $(grep ADMIN_EMAIL .admin-credentials | cut -d'=' -f2 | tr -d '\"')"
    echo "   • Password: ********"
    echo ""
    echo -e "${BLUE}🧪 Comandos de prueba:${NC}"
    echo ""
    echo "   # Cargar credenciales"
    echo "   source .admin-credentials"
    echo ""
    echo "   # Login y obtener token"
    echo "   TOKEN=\$(curl -s -X POST \"\$API_URL/api/v1/auth/login\" \\"
    echo "     -H \"Content-Type: application/json\" \\"
    echo "     -d '{\"email\":\"'\$ADMIN_EMAIL'\",\"password\":\"'\$ADMIN_PASSWORD'\",\"app_id\":\"'\$APP_ID'\"}' | \\"
    echo "     jq -r '.tokens.access_token')"
    echo ""
    echo "   # Probar endpoint protegido"
    echo "   curl -X GET \"\$API_URL/api/v1/users/me\" \\"
    echo "     -H \"Authorization: Bearer \$TOKEN\""
    echo ""
    echo -e "${BLUE}🛠️  Gestión:${NC}"
    echo "   • Ver logs:      docker-compose logs -f auth-service"
    echo "   • Detener todo:  make stop"
    echo "   • Estado DB:     make db-status"
    echo "   • Estado:        make status"
    echo ""
    echo -e "${GREEN}🎉 ¡Listo para desarrollar!${NC}"
}

# Función principal
main() {
    local email="$1"
    local password="$2"
    local first_name="$3"
    local last_name="$4"
    
    check_dependencies
    cleanup_previous
    generate_keys
    start_services
    wait_for_postgres
    # Las migraciones se ejecutan automáticamente en docker-entrypoint.sh
    verify_build
    wait_for_app
    
    if create_admin_user "$email" "$password" "$first_name" "$last_name"; then
        show_summary
    else
        echo -e "${RED}❌ Error creando usuario administrador${NC}"
        exit 1
    fi
}

# Ejecutar si es llamado directamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi