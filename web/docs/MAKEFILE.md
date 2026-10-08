# Makefile Commands Guide

The targets of `web/Makefile` (run them in `web/`). They wrap the npm scripts in
`package.json`. The repository root `Makefile` has the cross-component targets
(`make setup`, `make generate`, `make dev-web`, `make web-<script>`).

## Quick Start

```bash
# Show all available commands
make help

# Install dependencies
make install

# Run development server
make dev
```

## Development Commands

### Installation & Setup

| Command        | Description                            |
| -------------- | -------------------------------------- |
| `make install` | Install npm dependencies               |
| `make clean`   | Clean build artifacts and node_modules |

### Running the Application

| Command      | Description                                      |
| ------------ | ------------------------------------------------ |
| `make dev`   | Start development server (http://localhost:3000) |
| `make build` | Build production bundle                          |
| `make start` | Start production server                          |

### Code Quality

| Command             | Description                                       |
| ------------------- | ------------------------------------------------- |
| `make lint`         | Run ESLint                                        |
| `make lint-fix`     | Run ESLint with auto-fix                          |
| `make format`       | Format code with Prettier                         |
| `make format-check` | Check code formatting                             |
| `make type-check`   | Run TypeScript type checking                      |
| `make validate`     | Run all checks (type-check + lint + format-check) |

### Testing

| Command              | Description                     |
| -------------------- | ------------------------------- |
| `make test`          | Run tests                       |
| `make test-ui`       | Run tests with UI (interactive) |
| `make test-coverage` | Run tests with coverage report  |
| `make test-watch`    | Run tests in watch mode         |

### Bundle Analysis

| Command        | Description         |
| -------------- | ------------------- |
| `make analyze` | Analyze bundle size |

## Docker Commands

### Development

| Command             | Description                                     |
| ------------------- | ----------------------------------------------- |
| `make docker-dev`   | Start development with Docker (with hot reload) |
| `make docker-dev-d` | Start development in background                 |
| `make docker-down`  | Stop all Docker services                        |
| `make docker-logs`  | View Docker logs                                |
| `make docker-ps`    | Show running containers                         |

### Production

| Command             | Description                            |
| ------------------- | -------------------------------------- |
| `make docker-prod`  | Print how to start the production stack (`api/deploy`) |
| `make docker-clean` | Remove containers, volumes, and images |

## Git Hooks

Git hooks live in the repository root's `.githooks/` and are shared with the API
(there is no Husky any more). They are enabled by `git config core.hooksPath .githooks`,
which `make hooks` / `make setup` at the repository root run, and which `npm ci` /
`npm install` here also run (the `prepare` script).

| Command                   | Description                                                 |
| ------------------------- | ----------------------------------------------------------- |
| `make hooks` (root)       | Enable the repository hooks                                 |
| `make husky-install`      | Kept for compatibility: `npm install`, which runs `prepare` |
| `make pre-commit-install` | Same as `make hooks` at the root                            |

When `web/` files are staged, `.githooks/pre-commit` runs `npm run type-check` and
`lint-staged` (ESLint `--fix` + Prettier on staged files). `.githooks/commit-msg`
rejects AI attribution lines.

## Common Workflows

### First-time Setup

```bash
# 1. Install dependencies (also enables the repository git hooks)
make install

# 2. Copy environment file
cp .env.example .env.local
# Edit .env.local with your configuration

# 3. Run development server
make dev
```

### Daily Development

```bash
# Start dev server
make dev

# In another terminal, run tests in watch mode
make test-watch
```

### Before Committing

```bash
# Run all validation
make validate

# Run tests
make test

# The pre-commit hook runs type-check + lint-staged on commit
git commit -m "Your message"
```

### Docker Development

```bash
# Start with Docker (hot reload enabled)
make docker-dev

# View logs
make docker-logs

# Stop services
make docker-down
```

### Production Build

```bash
# Build and analyze
make build
make analyze

# Test production build locally
make start
```

## Environment Variables

### Development (.env.local)

Create `.env.local` from `.env.example`:

```bash
cp .env.example .env.local
```

Key variables (full list: [ops/ENVIRONMENT_VARIABLES.md](./ops/ENVIRONMENT_VARIABLES.md)):

- `BACKEND_API_URL` - Backend API URL (server-side only)
- `NEXT_PUBLIC_APP_URL` - Frontend URL (public)

### Docker Environment

When running with Docker:

- Environment variables are loaded from `.env.local` via `env_file`
- Some variables like `NODE_ENV` are overridden in `docker-compose.yml`
- To use a different API URL, edit `BACKEND_API_URL` in `.env.local`

## Hot Reload in Docker

The development Docker setup includes hot reload:

```bash
make docker-dev
```

Features:

- Source code mounted as volume (`.:/app`)
- File watching enabled (`WATCHPACK_POLLING`, `CHOKIDAR_USEPOLLING`)
- Changes auto-reload in browser
- Fast Refresh for React components

## Troubleshooting

### Hot reload not working in Docker

1. Check that polling is enabled:

   ```yaml
   environment:
     WATCHPACK_POLLING: 'true'
     CHOKIDAR_USEPOLLING: 'true'
   ```

2. Verify volumes are mounted:

   ```bash
   docker compose exec nextjs ls -la /app
   ```

3. Restart container:
   ```bash
   make docker-down
   make docker-dev
   ```

### Cannot connect to backend API

**Problem**: `ENOTFOUND host.docker.internal`

**Solution**:

1. Check `BACKEND_API_URL` in `.env.local`
2. On Linux, ensure `extra_hosts` is configured in `docker-compose.yml`:
   ```yaml
   extra_hosts:
     - 'host.docker.internal:host-gateway'
   ```
3. Or use the host's address: `BACKEND_API_URL=http://192.0.2.10:8080`

### Build failures

```bash
# Clean and reinstall
make clean
make install

# Rebuild Docker images
make docker-clean
make docker-dev
```

### Type errors

```bash
# Run type checker
make type-check

# Regenerate the API contract types (repository root)
make -C .. generate
```

## NPM Scripts vs Makefile

The Makefile wraps npm scripts for consistency with the API project:

| Makefile Command | NPM Script       |
| ---------------- | ---------------- |
| `make dev`       | `npm run dev`    |
| `make build`     | `npm run build`  |
| `make test`      | `npm run test`   |
| `make lint`      | `npm run lint`   |
| `make format`    | `npm run format` |

You can use either Makefile or npm scripts - they do the same thing!

## Related Documentation

- [Architecture](./ARCHITECTURE.md) - System architecture
- [Calling the API](./guides/API_INTEGRATION.md)
- [Docker and Sentry](./ops/DOCKER_SENTRY_SETUP.md)
