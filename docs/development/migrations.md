# Database Migrations

## Overview

OpenCTEM uses [golang-migrate](https://github.com/golang-migrate/migrate) for database migrations. Migration files are stored in the `migrations/` directory.

## Prerequisites

Install the migrate CLI (or use the Docker-based commands):

```bash
# Option 1: Install locally
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Option 2: Use make install-tools (installs all dev tools)
make install-tools

# Verify installation
migrate -version
```

## File Structure

```
migrations/
├── 000001_init_schema.up.sql       # Complete database schema
├── 000001_init_schema.down.sql     # Rollback (drop all tables)
├── _backup/                        # Archived old migrations (for reference)
└── seed/
    ├── seed_required.sql           # Required/essential data (empty by default)
    └── seed_test.sql               # Test/development data (users, tenants, etc.)
```

### Schema Philosophy

The migration structure follows these principles:

1. **Schema-only migrations**: Migrations contain ONLY database structure (tables, indexes, constraints, triggers, RLS policies)
2. **Separate seed data**: Data is managed separately through seed files
3. **Idempotent statements**: All DDL uses `IF NOT EXISTS` / `IF EXISTS` patterns
4. **Single consolidated schema**: One migration file contains the complete schema

### Seed Data Philosophy

Seed data is split into two categories:

1. **Required data** (`seed_required.sql`): Essential data the system needs to function
   - Currently empty - OpenCTEM creates all data dynamically
   - Add system configurations, default roles, etc. if needed

2. **Test data** (`seed_test.sql`): Development/testing data
   - Sample users, tenants, assets, projects, vulnerabilities, findings
   - **Never run in production!**

## Commands

### Quick Start (Development)

```bash
# Setup fresh database with test data
make db-fresh

# Or step by step:
make docker-reset-db      # Reset database
make docker-migrate-up    # Apply schema
make docker-seed-test     # Add test data
```

### Migration Commands

```bash
# Apply all migrations (Docker)
make docker-migrate-up

# Apply migrations (local - requires migrate CLI)
make migrate-up

# Rollback last migration
make docker-migrate-down  # Docker
make migrate-down         # Local

# Check current version
make docker-migrate-version  # Docker
make migrate-status          # Local

# Force version (use with caution!)
make docker-migrate-force version=1
```

### Seed Commands

```bash
# Seed required data only (production-safe)
make docker-seed-required

# Seed test data (development only!)
make docker-seed-test

# Seed all data (required + test)
make docker-seed
```

### Database Setup Commands

```bash
# Production setup: schema + required data
make db-setup

# Development setup: schema + all seed data
make db-setup-dev

# Fresh start: reset + schema + all seed data
make db-fresh
```

### Create New Migration

```bash
make migrate-create name=add_new_feature
```

This creates two files:
- `migrations/000002_add_new_feature.up.sql`
- `migrations/000002_add_new_feature.down.sql`

## Schema Overview

The `000001_init_schema.up.sql` contains:

### Extensions
- `uuid-ossp` - UUID generation

### Custom Types
- `user_status` - ENUM (active, inactive, suspended)

### Helper Functions
- `update_updated_at_column()` - Auto-update timestamps
- `calculate_project_risk_score()` - Risk calculation
- `update_project_stats()` - Trigger function for project stats
- `update_component_vuln_count()` - Trigger function for component vuln count
- `cleanup_old_audit_logs()` - Audit log retention

### Tables (14 total)
| Table | Description | Tenant-scoped |
|-------|-------------|---------------|
| `users` | User accounts | No (global) |
| `tenants` | Teams/organizations | No |
| `tenant_members` | User-tenant relationships | No |
| `tenant_invitations` | Pending invitations | No |
| `assets` | Asset inventory | Yes (RLS) |
| `exposures` | Asset exposures/vulnerabilities | Yes (RLS) |
| `attack_paths` | Attack path analysis | Yes (RLS) |
| `attack_path_nodes` | Attack path steps | Yes (RLS) |
| `projects` | Code repositories | Yes (RLS) |
| `components` | Software dependencies | Yes (RLS) |
| `vulnerabilities` | CVE catalog | No (global) |
| `findings` | Vulnerability instances | Yes (RLS) |
| `sessions` | User sessions | No |
| `refresh_tokens` | JWT refresh tokens | No |
| `audit_logs` | Audit trail | No |
| `email_logs` | Email tracking | No |

### Row-Level Security (RLS)

Tenant-scoped tables use RLS policies. Application must set tenant context before queries:

```sql
SET LOCAL app.current_tenant = 'tenant-uuid';
```

## Writing Migrations

### PostgreSQL Functions Convention

When creating database functions in migrations:

1. **Document in `docs/architecture/database-notes.md`** - Add function signature, description, and usage examples
2. **Use consistent naming** - `verb_noun_noun` pattern (e.g., `recover_stuck_platform_jobs`, `renew_agent_lease`)
3. **Return meaningful types** - Use `RETURNS TABLE` for complex results with multiple fields
4. **Include comments in SQL** - Use `COMMENT ON FUNCTION` for function documentation
5. **Match Go interface** - Ensure function signature matches the Go repository method that calls it

**Example:**
```sql
-- Function with proper documentation
CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(
    p_stuck_threshold_minutes INT DEFAULT 30
) RETURNS INT AS $$
DECLARE
    recovered_count INT;
BEGIN
    -- ... implementation
    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION recover_stuck_platform_jobs IS
    'Return stuck jobs to queue when agent goes offline (max 3 retries)';
```

**Go usage:**
```go
// Matches the DB function signature
func (r *CommandRepository) RecoverStuckJobs(ctx context.Context, thresholdMinutes int) (int64, error) {
    query := `SELECT recover_stuck_platform_jobs($1)`
    var count int64
    err := r.db.QueryRowContext(ctx, query, thresholdMinutes).Scan(&count)
    return count, err
}
```

### Best Practices

1. **Make statements idempotent**
```sql
-- Good: Won't fail if run twice
CREATE TABLE IF NOT EXISTS users (...);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- For constraints, use DO blocks
DO $$ BEGIN
    ALTER TABLE users ADD CONSTRAINT users_email_unique UNIQUE (email);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
```

2. **Always write both UP and DOWN**
```sql
-- Down should completely reverse UP
DROP TABLE IF EXISTS users;
DROP INDEX IF EXISTS idx_users_email;
```

3. **Test rollbacks**
```bash
make docker-migrate-up
make docker-migrate-down
make docker-migrate-up  # Should work again
```

4. **Never modify existing migrations after deployment**
   - Create new migration instead
   - Old migrations are backed up in `_backup/` for reference

## Environment Variables

Configure via `.env` file or environment:

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_USER` | Database user | (required) |
| `DB_PASSWORD` | Database password | (required) |
| `DB_NAME` | Database name | openctem |
| `DB_SSLMODE` | SSL mode | disable |

## Troubleshooting

### Dirty Database State

If a migration fails partially:

```bash
# Check current version
make docker-migrate-version
# Output: 1 (dirty)

# Fix the issue manually, then force version
make docker-migrate-force version=0  # Go back to before the failed migration

# Or force to current version if already fixed
make docker-migrate-force version=1

# Re-run migrations
make docker-migrate-up
```

### Complete Reset (Development)

```bash
# Nuclear option: reset everything
make db-fresh
```

### Check Schema Migrations Table

```bash
make docker-psql
# Then in psql:
SELECT * FROM schema_migrations;
```

### Test User Credentials

When using `seed_test.sql`, all users have:
- **Password**: `Password123`
- **Hash**: `$2a$12$lAqs23AmzWlMNDCUaUuuceAWEw/EzF25N/oLnSfa1gUldIRllsqHG`

Test accounts:
- `admin@openctem.io` - Admin user
- `nguyen.an@techviet.vn` - Regular user
- (see `seed_test.sql` for full list)

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run migrations
  run: make docker-migrate-up
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### Production Deployment

```bash
# 1. Apply migrations
make docker-migrate-up

# 2. (Optional) Seed required data
make docker-seed-required

# 3. Start application
./server
```

**Never run `docker-seed-test` in production!**
