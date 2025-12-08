.PHONY: all build run clean test docker-up docker-down docker-logs keys migrate migrate-rbac db-reset db-status create-admin setup quickstart help dev fmt tidy

# Variables
APP_NAME=auth-service
BINARY_DIR=bin
BINARY=$(BINARY_DIR)/$(APP_NAME)

all: help

## build: Compilar la aplicación
build:
	@echo "🔨 Construyendo $(APP_NAME)..."
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY) cmd/main.go
	@echo "✓ Build completo: $(BINARY)"

## run: Ejecutar la aplicación (sin Docker)
run: build
	@echo "🚀 Ejecutando $(APP_NAME)..."
	@./$(BINARY)

## clean: Limpiar archivos generados
clean:
	@echo "🧹 Limpiando..."
	@rm -rf $(BINARY_DIR)
	@echo "✓ Limpieza completa"

## test: Ejecutar tests
test:
	@echo "🧪 Ejecutando tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✓ Tests completos"

## coverage: Generar reporte de cobertura
coverage: test
	@go tool cover -html=coverage.out

## docker-up: Iniciar todos los servicios con Docker Compose
docker-up:
	@echo "🐳 Iniciando servicios..."
	@docker-compose up -d
	@echo "✓ Servicios iniciados"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis: localhost:6379"
	@echo "  - Auth Service: http://localhost:8080"

## docker-down: Detener todos los servicios
docker-down:
	@echo "🛑 Deteniendo servicios..."
	@docker-compose down
	@echo "✓ Servicios detenidos"

## docker-logs: Ver logs de los servicios
docker-logs:
	@docker-compose logs -f

## docker-build: Construir imagen Docker
docker-build:
	@echo "🐳 Construyendo imagen Docker..."
	@docker-compose build
	@echo "✓ Imagen Docker construida"

## keys: Generar par de claves RSA para JWT
keys:
	@echo "🔑 Generando claves RSA..."
	@bash scripts/generate-keys.sh

## migrate: Ejecutar migración inicial de base de datos
migrate:
	@echo "📊 Ejecutando migración inicial..."
	@echo "  → Migración 001: Schema completo multi-tenant..."
	@docker-compose exec -T postgres psql -U auth -d authdb < migrations/001_initial.sql
	@echo "✓ Migración completa"

## migrate-rbac: DEPRECATED - RBAC ya está incluido en 001_initial.sql
migrate-rbac:
	@echo "⚠️  Este comando está deprecado."
	@echo "   RBAC ya está incluido en la migración 001_initial.sql"
	@echo "   Usa 'make migrate' en su lugar"

## db-reset: Resetear completamente la base de datos (⚠️  BORRA TODOS LOS DATOS)
db-reset:
	@echo "⚠️  ADVERTENCIA: Esto borrará TODOS los datos de la base de datos"
	@read -p "¿Estás seguro? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "🗑️  Eliminando base de datos..."; \
		docker-compose exec postgres psql -U auth -d postgres -c "DROP DATABASE IF EXISTS authdb;"; \
		echo "🔨 Creando base de datos..."; \
		docker-compose exec postgres psql -U auth -d postgres -c "CREATE DATABASE authdb;"; \
		echo "📊 Ejecutando migración inicial..."; \
		docker-compose exec -T postgres psql -U auth -d authdb < migrations/001_initial.sql; \
		echo "✓ Base de datos reseteada completamente"; \
	else \
		echo "❌ Operación cancelada"; \
	fi

## db-status: Ver estado de la base de datos
db-status:
	@echo "📊 Estado de la base de datos:"
	@echo ""
	@echo "📋 Tablas:"
	@docker-compose exec postgres psql -U auth -d authdb -c "\dt"
	@echo ""
	@echo "👥 Total de usuarios:"
	@docker-compose exec postgres psql -U auth -d authdb -c "SELECT COUNT(*) as total_users FROM users;"
	@echo ""
	@echo "🎭 Roles disponibles:"
	@docker-compose exec postgres psql -U auth -d authdb -c "SELECT name, description FROM roles ORDER BY name;"
	@echo ""
	@echo "🔑 Permisos totales:"
	@docker-compose exec postgres psql -U auth -d authdb -c "SELECT COUNT(*) as total_permissions FROM permissions;"

## create-admin: Crear script para promover usuario a admin
create-admin:
	@echo "🔐 Creando usuario administrador..."
	@read -p "Email del usuario a promover a admin: " email; \
	docker-compose exec postgres psql -U auth -d authdb -c "INSERT INTO user_roles (user_id, role_id, assigned_at) SELECT u.id, '20000000-0000-0000-0000-000000000002', NOW() FROM users u WHERE u.email = '$$email' ON CONFLICT (user_id, role_id) DO NOTHING;" && \
	echo "✓ Usuario $$email promovido a admin" || \
	echo "❌ Error: Usuario no encontrado o ya es admin"

## tidy: Organizar dependencias
tidy:
	@echo "📦 Organizando dependencias..."
	@go mod tidy
	@go mod verify
	@echo "✓ Dependencias organizadas"

## fmt: Formatear código
fmt:
	@echo "✨ Formateando código..."
	@go fmt ./...
	@echo "✓ Código formateado"

## dev: Configurar entorno de desarrollo (keys + docker + migrate)
dev: keys docker-up
	@echo "⏳ Esperando a que PostgreSQL esté listo..."
	@sleep 5
	@$(MAKE) migrate
	@echo ""
	@echo "✓ Entorno de desarrollo listo!"
	@echo ""
	@echo "📍 Endpoints disponibles:"
	@echo "  - Health: http://localhost:8080/health"
	@echo "  - API:    http://localhost:8080/api/v1"
	@echo "  - Docs:   file://$(PWD)/docs/openapi.yaml"
	@echo ""
	@echo "🗄️  Base de datos:"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis: localhost:6379"
	@echo ""
	@echo "📝 Próximos pasos:"
	@echo "  1. Compilar: make build"
	@echo "  2. Ejecutar: make run"
	@echo "  3. Crear admin: make create-admin"
	@echo "  4. Ver estado DB: make db-status"

## setup: Setup completo inicial (dev + build + run en background)
setup: dev build
	@echo ""
	@echo "🚀 Iniciando servicio en background..."
	@nohup ./$(BINARY) > logs/auth-service.log 2>&1 &
	@echo $$! > .pid
	@echo "✓ Servicio iniciado (PID: $$(cat .pid))"
	@echo ""
	@echo "📋 Comandos útiles:"
	@echo "  - Ver logs:      tail -f logs/auth-service.log"
	@echo "  - Detener:       kill $$(cat .pid)"
	@echo "  - Estado DB:     make db-status"
	@echo "  - Crear admin:   make create-admin"
	@echo ""
	@echo "💡 Para desarrollo con hot-reload, usa: make run"

## quickstart: 🚀 Inicio rápido completo - Todo listo para testear en un comando
quickstart:
	@echo "🚀 Ejecutando setup completo automatizado..."
	@chmod +x scripts/full-setup.sh
	@bash scripts/full-setup.sh

## quickstart-custom: 🚀 Quickstart con credenciales personalizadas
quickstart-custom:
	@echo "🚀 Setup con credenciales personalizadas..."
	@read -p "Email del admin: " email; \
	read -s -p "Password: " password; echo; \
	read -p "Nombre: " first_name; \
	read -p "Apellido: " last_name; \
	chmod +x scripts/full-setup.sh; \
	bash scripts/full-setup.sh "$$email" "$$password" "$$first_name" "$$last_name"

## stop: Detener aplicación y servicios
stop:
	@echo "🛑 Deteniendo servicios..."
	@if [ -f .pid ]; then \
		echo "Deteniendo aplicación (PID: $$(cat .pid))"; \
		kill $$(cat .pid) 2>/dev/null || true; \
		rm -f .pid; \
	fi
	@$(MAKE) docker-down --no-print-directory
	@echo "✓ Todos los servicios detenidos"

## restart: Reiniciar todo el sistema
restart: stop quickstart

## logs: Ver logs de la aplicación
logs:
	@if [ -f logs/auth-service.log ]; then \
		tail -f logs/auth-service.log; \
	else \
		echo "⚠️  No hay logs disponibles. ¿Está la aplicación ejecutándose?"; \
	fi

## status: Ver estado completo del sistema
status:
	@echo "📊 Estado del Sistema Auth Service"
	@echo ""
	@echo "🐳 Docker Containers:"
	@docker-compose ps 2>/dev/null || echo "  No hay containers ejecutándose"
	@echo ""
	@echo "📱 Aplicación:"
	@if [ -f .pid ]; then \
		pid=$$(cat .pid); \
		if ps -p $$pid > /dev/null 2>&1; then \
			echo "  ✓ Ejecutándose (PID: $$pid)"; \
		else \
			echo "  ❌ PID file existe pero proceso no está ejecutándose"; \
			rm -f .pid; \
		fi; \
	else \
		echo "  ❌ No está ejecutándose"; \
	fi
	@echo ""
	@echo "🌐 API Health:"
	@curl -s http://localhost:8080/health 2>/dev/null && echo "  ✓ API respondiendo" || echo "  ❌ API no disponible"
	@echo ""
	@if docker-compose ps postgres | grep -q "Up"; then \
		$(MAKE) db-status --no-print-directory; \
	else \
		echo "📊 Base de datos: No disponible"; \
	fi

## admin-login: Hacer login rápido con credenciales de admin guardadas
admin-login:
	@if [ -f .admin-credentials ]; then \
		source .admin-credentials && \
		echo "🔑 Haciendo login como admin..." && \
		TOKEN=$$(curl -s -X POST "$$API_URL/api/v1/auth/login" \
			-H "Content-Type: application/json" \
			-d "{\"email\":\"$$ADMIN_EMAIL\",\"password\":\"$$ADMIN_PASSWORD\",\"app_id\":\"$$APP_ID\"}" | \
			jq -r '.tokens.access_token' 2>/dev/null) && \
		if [ "$$TOKEN" != "null" ] && [ -n "$$TOKEN" ]; then \
			echo "✓ Login exitoso"; \
			echo "Token: $$TOKEN"; \
			echo ""; \
			echo "Exportar token:"; \
			echo "  export ADMIN_TOKEN=\"$$TOKEN\""; \
		else \
			echo "❌ Error en login"; \
		fi; \
	else \
		echo "❌ No se encontraron credenciales de admin. Ejecuta 'make quickstart' primero."; \
	fi

## help: Mostrar esta ayuda
help:
	@echo "Uso: make [target]"
	@echo ""
	@echo "Targets disponibles:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/  /'

