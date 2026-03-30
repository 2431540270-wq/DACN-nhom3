-- ============================================================
-- migrate.sql — Fix missing columns in the logs table
-- ============================================================
-- Run this file when you see errors like:
--   "[DB] SELECT error: Unknown column 'attack_type' in 'field list'"
--   "[DB] INSERT error: Unknown column 'attack_type' in 'field list'"
--
-- How to run:
--   Open MySQL Workbench -> connect to localhost:3306
--   Open this file -> click the ⚡ Execute button
-- ============================================================

USE security_logs;

-- ============================================================
-- STEP 1: Check current table structure
-- ============================================================
DESCRIBE logs;

-- ============================================================
-- STEP 2: Add missing columns if they don't exist
-- (Using a stored procedure because MySQL doesn't support
--  ALTER TABLE ... ADD COLUMN IF NOT EXISTS directly)
-- ============================================================
DROP PROCEDURE IF EXISTS fix_missing_columns;

DELIMITER $$

CREATE PROCEDURE fix_missing_columns()
BEGIN

    -- Fix: attack_type column
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'security_logs'
          AND TABLE_NAME   = 'logs'
          AND COLUMN_NAME  = 'attack_type'
    ) THEN
        ALTER TABLE logs
            ADD COLUMN attack_type VARCHAR(50) NOT NULL DEFAULT 'NORMAL'
            AFTER status;

        UPDATE logs SET attack_type = 'NORMAL' WHERE attack_type IS NULL OR attack_type = '';

        SELECT 'OK: Column attack_type added.' AS migration_result;
    ELSE
        SELECT 'SKIP: Column attack_type already exists.' AS migration_result;
    END IF;

    -- Fix: description column
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'security_logs'
          AND TABLE_NAME   = 'logs'
          AND COLUMN_NAME  = 'description'
    ) THEN
        ALTER TABLE logs
            ADD COLUMN description TEXT
            AFTER attack_type;

        SELECT 'OK: Column description added.' AS migration_result;
    ELSE
        SELECT 'SKIP: Column description already exists.' AS migration_result;
    END IF;

    -- Fix: status column (set default if missing)
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'security_logs'
          AND TABLE_NAME   = 'logs'
          AND COLUMN_NAME  = 'status'
    ) THEN
        ALTER TABLE logs
            ADD COLUMN status VARCHAR(50) DEFAULT 'PASS'
            AFTER action;

        SELECT 'OK: Column status added.' AS migration_result;
    ELSE
        SELECT 'SKIP: Column status already exists.' AS migration_result;
    END IF;

END$$

DELIMITER ;

CALL fix_missing_columns();

DROP PROCEDURE IF EXISTS fix_missing_columns;

-- ============================================================
-- STEP 3: Verify the table structure after migration
-- ============================================================
DESCRIBE logs;

-- ============================================================
-- STEP 4: Preview the most recent rows
-- ============================================================
SELECT id, ip_address, action, status, attack_type, description
FROM logs
ORDER BY id DESC
LIMIT 10;
