-- vm_asset_edits
-- ----------------------------------------------------------------------------
-- Local overlay table for the Asset Editor page.
-- Stores per-VM user edits (Asset Name, IP, Hostname, OS Type, OS Version)
-- keyed on (source_host, vm_name). The upstream Asset Inventory API is
-- never modified — this table is the local source of truth for edits only.
--
-- Apply with:
--     psql "$DATABASE_URL" -f sql/create_vm_asset_edits.sql
--
-- Safe to run repeatedly: every statement uses IF NOT EXISTS.
-- ----------------------------------------------------------------------------

BEGIN;

CREATE TABLE IF NOT EXISTS vm_asset_edits (
    id          SERIAL       PRIMARY KEY,
    source_host VARCHAR(255) NOT NULL,
    vm_name     VARCHAR(255) NOT NULL,
    asset_name  VARCHAR(255),
    hostname    VARCHAR(255),
    ip_address  VARCHAR(255),
    os_type     VARCHAR(255),
    os_version  TEXT,
    updated_at  TIMESTAMP
);

-- Lookup index: the app reads/writes by (source_host, vm_name).
CREATE INDEX IF NOT EXISTS idx_vm_asset_edits_host_name
    ON vm_asset_edits (source_host, vm_name);

-- One edit row per (source_host, vm_name) pair.
-- Wrapped in a DO block so the script stays idempotent even though
-- ADD CONSTRAINT itself has no IF NOT EXISTS clause in PostgreSQL < 16.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_vm_asset_edits_host_name'
    ) THEN
        ALTER TABLE vm_asset_edits
            ADD CONSTRAINT uq_vm_asset_edits_host_name
            UNIQUE (source_host, vm_name);
    END IF;
END $$;

COMMIT;

-- Verify
SELECT
    column_name,
    data_type,
    character_maximum_length,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'vm_asset_edits'
ORDER BY ordinal_position;
