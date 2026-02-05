# Makefile Commands Guide

This document provides a comprehensive guide to using Makefile commands for the Rediver API project.

## Quick Start

```bash
# Show all available commands
make help

# Install development tools
make install-tools

# Run development server with hot reload
make dev
```

## Development Commands

### Building & Running

| Command | Description |
|---------|-------------|
| `make build` | Build the binary |
| `make run` | Run the application directly |
| `make dev` | Run with hot reload (requires air) |
| `make clean` | Clean build artifacts |

### Code Quality

| Command | Description |
|---------|-------------|
| `make lint` | Run linter (golangci-lint) |
| `make fmt` | Format code with gofmt |
| `make tidy` | Tidy Go dependencies |
| `make test` | Run all tests |
| `make test-coverage` | Run tests with coverage report |

### Documentation

| Command | Description |
|---------|-------------|
| `make swagger` | Generate Swagger documentation |
| `make swagger-install` | Install Swagger CLI tool |

## Docker Commands

### Development

| Command | Description |
|---------|-------------|
| `make docker-dev` | Start development environment |
| `make docker-dev-d` | Start development in background |
| `make docker-down` | Stop all services |
| `make docker-logs` | View logs |
| `make docker-logs-app` | View only app logs |
| `make docker-ps` | Show running containers |

### Production

| Command | Description |
|---------|-------------|
| `make docker-build` | Build production image |
| `make docker-prod` | Start production environment |
| `make docker-clean` | Remove containers, volumes, images |

## Database Commands

### Migrations

| Command | Description |
|---------|-------------|
| `make migrate-up` | Run migrations (local) |
| `make migrate-down` | Rollback last migration (local) |
| `make migrate-create name=<name>` | Create new migration |
| `make migrate-status` | Show migration status |
| `make docker-migrate-up` | Run migrations in Docker |
| `make docker-migrate-down` | Rollback in Docker |
| `make docker-migrate-version` | Show migration version |

### Database Setup

| Command | Description |
|---------|-------------|
| `make db-setup` | Setup database (schema + required data) |
| `make db-setup-dev` | Setup with test data |
| `make db-fresh` | Reset and setup from scratch |
| `make docker-reset-db` | Reset database |
| `make docker-psql` | Open psql shell in Docker |

### Seeding

| Command | Description |
|---------|-------------|
| `make seed-required` | Seed required data (local) |
| `make docker-seed-comprehensive` | Seed comprehensive data |
| `make docker-seed-access-control` | Seed access control data |

## Security & Pre-commit

### Installation

```bash
# Install pre-commit hooks (auto-installs dependencies on Linux)
make pre-commit-install
```

This command automatically:
- Installs `pip` (if on Ubuntu/Debian)
- Installs `pre-commit` tool
- Installs `Go` (if not present)
- Installs `gitleaks` for secret detection
- Installs `trivy` for vulnerability scanning
- Installs `hadolint` for Dockerfile linting

### Usage

| Command | Description |
|---------|-------------|
| `make pre-commit-run` | Run all hooks on all files |
| `make pre-commit-update` | Update hooks to latest versions |
| `make security-scan` | Full security scan (gitleaks + gosec + trivy) |
| `make gitleaks` | Run gitleaks only |

## Tool Installation

```bash
# Install all development tools
make install-tools
```

Installs:
- golangci-lint
- air (hot reload)
- migrate (database migrations)
- mockgen (mock generation)

## Common Workflows

### First-time Setup

```bash
# 1. Install tools
make install-tools

# 2. Install pre-commit hooks
make pre-commit-install

# 3. Setup database
make db-setup-dev

# 4. Run development server
make dev
```

### Daily Development

```bash
# Start development
make dev

# Run tests
make test

# Check code quality
make lint
make test
```

### Before Committing

```bash
# Format code
make fmt

# Run all checks
make lint
make test

# Pre-commit hooks will run automatically on git commit
```

### Docker Development

```bash
# Start services
make docker-dev

# View logs
make docker-logs-app

# Stop services
make docker-down
```

## Environment Variables

Database configuration is loaded from `.env` file:
- `DB_HOST` - Database host (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name (default:.exploop)

## Troubleshooting

### Pre-commit installation fails

If `make pre-commit-install` fails:
1. Ensure you're on a supported platform (Ubuntu/Debian or macOS)
2. On Ubuntu, the Makefile will auto-install pip
3. On macOS, ensure Homebrew is installed

### Migration errors

```bash
# Check migration status
make migrate-status

# Force migration to specific version
make docker-migrate-force version=X
```

### Docker issues

```bash
# Clean everything and restart
make docker-clean
make docker-dev
```
