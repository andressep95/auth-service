# Database Migrations

## Migration Files

### Core Schema
- **001_initial.sql** - Initial database schema (users, roles, permissions, sessions, apps, audit_logs)
- **002_seed_default_roles.sql** - Default roles and permissions setup
- **003_add_email_verification.sql** - Email verification fields in users table

### Cleanup & Refactoring
- **004_cleanup_unused_tables.sql** - Removes unused `email_verifications` and `password_resets` tables

## Running Migrations

### New Installation
```bash
# All migrations are applied automatically on first run
make migrate
```

### Existing Installation (Cleanup)
If you have an existing database with the unused tables, run:

```bash
# Apply cleanup migration
docker-compose exec postgres psql -U auth -d authdb -f /migrations/004_cleanup_unused_tables.sql

# Or manually
docker-compose exec postgres psql -U auth -d authdb
\i /migrations/004_cleanup_unused_tables.sql
```

**Safe to run:** The cleanup migration uses `DROP TABLE IF EXISTS CASCADE`, so it's safe to run even if tables don't exist.

## Migration 004: Why These Tables Were Removed

### Email Verifications
- ❌ **Removed table:** `email_verifications`
- ✅ **Current implementation:** Uses fields in `users` table:
  - `email_verification_token`
  - `email_verification_token_expires_at`

### Password Resets
- ❌ **Removed table:** `password_resets`
- ✅ **Current implementation:** Uses fields in `users` table:
  - `password_reset_token`
  - `password_reset_token_expires_at`

### Benefits
- Simpler schema with fewer tables
- No joins needed for verification/reset operations
- Easier to maintain and understand
- Same functionality, cleaner implementation

## Rollback (If Needed)

If you need to recreate these tables (not recommended), you can find the original schema in git history:

```bash
git show 669ca69:migrations/001_initial.sql | grep -A 20 "email_verifications\|password_resets"
```

**Note:** Rolling back requires migrating existing tokens from users table to the new tables.
