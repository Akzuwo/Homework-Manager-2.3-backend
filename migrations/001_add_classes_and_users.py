"""Database migration for classes, users, and related tables."""

from __future__ import annotations

import datetime
import os
import pathlib
import sys
from typing import Optional

import mysql.connector
from mysql.connector import errorcode

BASE_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth.utils import hash_password

DB_CONFIG = {
    "host": "mc-mysql01.mc-host24.de",
    "user": "u4203_Mtc42FNhxN",
    "password": "nA6U=8ecQBe@vli@SKXN9rK9",
    "database": "s4203_reports",
    "port": 3306,
}

DEFAULT_CLASS_SLUG = "default"

SEED_ADMIN_EMAIL = os.getenv("SEED_ADMIN_EMAIL", "admin@localhost")
SEED_ADMIN_PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "ChangeMe123!")


def _connect() -> mysql.connector.MySQLConnection:
    return mysql.connector.connect(**DB_CONFIG)


def _table_exists(cursor: mysql.connector.cursor.MySQLCursor, table_name: str) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (table_name,))
    return cursor.fetchone() is not None


def _column_exists(cursor: mysql.connector.cursor.MySQLCursor, table: str, column: str) -> bool:
    cursor.execute(f"SHOW COLUMNS FROM `{table}` LIKE %s", (column,))
    return cursor.fetchone() is not None


def _ensure_classes_table(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS classes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            slug VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_classes_slug (slug),
            UNIQUE KEY uq_classes_title (title)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def _ensure_users_table(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('student','teacher','admin') NOT NULL DEFAULT 'student',
            class_id INT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            last_login_at DATETIME NULL,
            email_verified_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_users_email (email),
            INDEX idx_users_class_id (class_id),
            CONSTRAINT fk_users_class FOREIGN KEY (class_id)
                REFERENCES classes(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )

    if not _column_exists(cursor, "users", "email_verified_at"):
        cursor.execute(
            "ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL AFTER last_login_at"
        )


def _ensure_email_verifications_table(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            email VARCHAR(255) NOT NULL,
            token VARCHAR(255) NOT NULL,
            expires_at DATETIME NOT NULL,
            verified_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_email_verifications_token (token),
            INDEX idx_email_verifications_user (user_id),
            CONSTRAINT fk_email_verifications_user FOREIGN KEY (user_id)
                REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def _ensure_class_schedules_table(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS class_schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            class_id INT NOT NULL,
            source VARCHAR(255) NULL,
            import_hash VARCHAR(64) NULL,
            imported_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_class_schedules_class (class_id),
            CONSTRAINT fk_class_schedules_class FOREIGN KEY (class_id)
                REFERENCES classes(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def _ensure_admin_audit_logs_table(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            actor_id INT NOT NULL,
            action VARCHAR(64) NOT NULL,
            entity_type VARCHAR(64) NOT NULL,
            entity_id INT NULL,
            details JSON NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_admin_audit_actor (actor_id),
            INDEX idx_admin_audit_entity (entity_type, entity_id),
            CONSTRAINT fk_admin_audit_actor FOREIGN KEY (actor_id)
                REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def _ensure_table_engine(
    cursor: mysql.connector.cursor.MySQLCursor, table: str, engine: str = "InnoDB"
) -> None:
    cursor.execute("SHOW TABLE STATUS LIKE %s", (table,))
    row = cursor.fetchone()
    if row is None:
        return
    current_engine = row[1]
    if current_engine != engine:
        cursor.execute(f"ALTER TABLE `{table}` ENGINE={engine}")


def _get_default_class_id(cursor: mysql.connector.cursor.MySQLCursor) -> int:
    cursor.execute("SELECT id FROM classes WHERE slug=%s", (DEFAULT_CLASS_SLUG,))
    row = cursor.fetchone()
    if row:
        return int(row[0])
    cursor.execute(
        "INSERT INTO classes (slug, title, description, is_active, created_at, updated_at)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (
            DEFAULT_CLASS_SLUG,
            "Standardklasse",
            "Standardklasse für bestehende Daten",
            1,
            datetime.datetime.utcnow(),
            datetime.datetime.utcnow(),
        ),
    )
    return cursor.lastrowid


def _ensure_stundenplan_entries(
    cursor: mysql.connector.cursor.MySQLCursor, default_class_id: int
) -> None:
    if not _table_exists(cursor, "stundenplan_entries"):
        cursor.execute(
            """
            CREATE TABLE stundenplan_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                class_id INT NOT NULL,
                tag VARCHAR(16) NOT NULL,
                start VARCHAR(8) NOT NULL,
                `end` VARCHAR(8) NOT NULL,
                fach VARCHAR(100) NOT NULL,
                raum VARCHAR(50) NOT NULL,
                INDEX idx_stundenplan_class_day (class_id, tag, start),
                CONSTRAINT fk_stundenplan_entries_class FOREIGN KEY (class_id)
                    REFERENCES classes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
        return

    _ensure_table_engine(cursor, "stundenplan_entries")

    if not _column_exists(cursor, "stundenplan_entries", "class_id"):
        cursor.execute(
            "ALTER TABLE stundenplan_entries ADD COLUMN class_id INT NULL AFTER id"
        )
        cursor.execute(
            "ALTER TABLE stundenplan_entries ADD INDEX idx_stundenplan_class_day (class_id, tag, start)"
        )
        cursor.execute(
            "UPDATE stundenplan_entries SET class_id = %s WHERE class_id IS NULL",
            (default_class_id,),
        )
        cursor.execute(
            "ALTER TABLE stundenplan_entries MODIFY COLUMN class_id INT NOT NULL"
        )
    else:
        cursor.execute(
            "SHOW INDEX FROM stundenplan_entries WHERE Key_name = 'idx_stundenplan_class_day'"
        )
        if cursor.fetchone() is None:
            cursor.execute(
                "ALTER TABLE stundenplan_entries ADD INDEX idx_stundenplan_class_day (class_id, tag, start)"
            )

    try:
        cursor.execute(
            "ALTER TABLE stundenplan_entries ADD CONSTRAINT fk_stundenplan_entries_class "
            "FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE"
        )
    except mysql.connector.Error as exc:  # pragma: no cover - depends on DB state
        if exc.errno not in {
            errorcode.ER_DUP_KEYNAME,
            errorcode.ER_CANNOT_ADD_FOREIGN,
            errorcode.ER_FK_DUP_NAME,
        }:
            raise


def _ensure_seed_admin_user(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    cursor.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if cursor.fetchone():
        return

    password_hash = hash_password(SEED_ADMIN_PASSWORD)
    now = datetime.datetime.utcnow()
    cursor.execute(
        """
        INSERT INTO users (email, password_hash, role, is_active, created_at, updated_at)
        VALUES (%s, %s, 'admin', 1, %s, %s)
        """,
        (SEED_ADMIN_EMAIL, password_hash, now, now),
    )
    print(
        "Seed admin user created with email '",
        SEED_ADMIN_EMAIL,
        "'. Please change the password after the first login.",
        sep="",
    )


def _run_migration() -> None:
    conn = _connect()
    cursor: Optional[mysql.connector.cursor.MySQLCursor] = None
    try:
        cursor = conn.cursor()
        _ensure_classes_table(cursor)
        _ensure_users_table(cursor)
        _ensure_email_verifications_table(cursor)
        _ensure_class_schedules_table(cursor)
        _ensure_admin_audit_logs_table(cursor)
        _ensure_seed_admin_user(cursor)
        default_class_id = _get_default_class_id(cursor)
        _ensure_stundenplan_entries(cursor, default_class_id)
        conn.commit()
        print("Migration completed successfully.")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


if __name__ == "__main__":
    try:
        _run_migration()
    except mysql.connector.Error as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        sys.exit(1)
