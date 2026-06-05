-- migrate_v2_auth_drift.sql
-- ----------------------------------------------------------------------------
-- Schema additions for the v2 feature set:
--   * Multi-user authentication      (users table)
--   * In-app notifications           (notifications table)
--   * Capacity / snapshot fields      (new vm_inventory columns)
--
-- The application creates these automatically on startup (SQLAlchemy
-- create_all + an ADD COLUMN IF NOT EXISTS migration). This script is provided
-- for operators who prefer to migrate the database manually / out-of-band.
--
-- Apply with:
--     psql "$DATABASE_URL" -f sql/migrate_v2_auth_drift.sql
--
-- Safe to run repeatedly: every statement uses IF NOT EXISTS.
-- ----------------------------------------------------------------------------

BEGIN;

-- ── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL       PRIMARY KEY,
    username      VARCHAR(150) NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    role          VARCHAR(20)  DEFAULT 'viewer',   -- 'admin' | 'viewer'
    active        BOOLEAN      DEFAULT TRUE,
    created_at    TIMESTAMP,
    last_login    TIMESTAMP
);

-- ── Notifications ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
    id         SERIAL      PRIMARY KEY,
    created_at TIMESTAMP   NOT NULL,
    level      VARCHAR(16) DEFAULT 'info',         -- info | warning | error
    category   VARCHAR(64),                        -- discovery | drift | asset | system
    host       VARCHAR(255),
    message    TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at
    ON notifications (created_at DESC);

-- ── Capacity / snapshot columns on vm_inventory ──────────────────────────────
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS num_cpu                INTEGER;
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS memory_mb              INTEGER;
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS storage_committed_gb   VARCHAR(32);
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS storage_uncommitted_gb VARCHAR(32);
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS datastores             TEXT;
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS snapshot_count         INTEGER;
ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS snapshot_oldest        VARCHAR(64);

-- Helps the "latest snapshot per host" and drift queries.
CREATE INDEX IF NOT EXISTS idx_vm_inventory_host_discovered
    ON vm_inventory (source_host, discovered_at DESC);

COMMIT;
