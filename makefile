.PHONY: all build run clean test docker-up docker-down docker-logs keys migrate help dev fmt tidy

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

## migrate: Ejecutar migraciones de base de datos
migrate:
	@echo "📊 Ejecutando migraciones..."
	@docker-compose exec -T postgres psql -U auth -d authdb < migrations/001_initial.sql || true
	@echo "✓ Migraciones completas"

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

## dev: Configurar entorno de desarrollo (keys + docker)
dev: keys docker-up
	@echo "✓ Entorno de desarrollo listo!"
	@echo ""
	@echo "Endpoints disponibles:"
	@echo "  - Health: http://localhost:8080/health"
	@echo "  - API:    http://localhost:8080/api/v1"
	@echo ""
	@echo "Base de datos:"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis: localhost:6379"

## help: Mostrar esta ayuda
help:
	@echo "Uso: make [target]"
	@echo ""
	@echo "Targets disponibles:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/  /'

