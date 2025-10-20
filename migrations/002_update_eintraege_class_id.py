"""Ensure eintraege.class_id uses constrained VARCHAR values."""

from __future__ import annotations

import pathlib
import sys

import mysql.connector

BASE_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from class_ids import DEFAULT_ENTRY_CLASS_ID, ENTRY_CLASS_IDS

DB_CONFIG = {
    "host": "mc-mysql01.mc-host24.de",
    "user": "u4203_Mtc42FNhxN",
    "password": "nA6U=8ecQBe@vli@SKXN9rK9",
    "database": "s4203_reports",
    "port": 3306,
}

ALLOWED_VALUES_SQL = ", ".join(f"'{value}'" for value in ENTRY_CLASS_IDS)


def _connect() -> mysql.connector.MySQLConnection:
    return mysql.connector.connect(**DB_CONFIG)


def _table_exists(cursor: mysql.connector.cursor.MySQLCursor, table_name: str) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (table_name,))
    return cursor.fetchone() is not None


def _column_exists(cursor: mysql.connector.cursor.MySQLCursor, table_name: str, column_name: str) -> bool:
    cursor.execute(f"SHOW COLUMNS FROM `{table_name}` LIKE %s", (column_name,))
    return cursor.fetchone() is not None


def _drop_existing_checks(cursor: mysql.connector.cursor.MySQLCursor, table_name: str) -> None:
    cursor.execute(
        """
        SELECT CONSTRAINT_NAME
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND CONSTRAINT_TYPE = 'CHECK'
        """,
        (table_name,),
    )
    for (constraint_name,) in cursor.fetchall():
        cursor.execute(f"ALTER TABLE `{table_name}` DROP CHECK `{constraint_name}`")


def _update_class_id_column(cursor: mysql.connector.cursor.MySQLCursor) -> None:
    if not _table_exists(cursor, "eintraege"):
        return

    if not _column_exists(cursor, "eintraege", "class_id"):
        cursor.execute(
            f"ALTER TABLE eintraege ADD COLUMN class_id VARCHAR(4) NOT NULL DEFAULT '{DEFAULT_ENTRY_CLASS_ID}' AFTER id"
        )
    else:
        cursor.execute(
            f"ALTER TABLE eintraege MODIFY COLUMN class_id VARCHAR(4) NOT NULL DEFAULT '{DEFAULT_ENTRY_CLASS_ID}'"
        )

    cursor.execute(
        f"""
        UPDATE eintraege
        SET class_id = '{DEFAULT_ENTRY_CLASS_ID}'
        WHERE class_id IS NULL
           OR TRIM(class_id) = ''
           OR class_id NOT IN ({ALLOWED_VALUES_SQL})
        """
    )

    _drop_existing_checks(cursor, "eintraege")
    cursor.execute(
        f"ALTER TABLE eintraege ADD CONSTRAINT chk_eintraege_class_id CHECK (class_id IN ({ALLOWED_VALUES_SQL}))"
    )


def run() -> None:
    conn = _connect()
    try:
        cursor = conn.cursor()
        try:
            _update_class_id_column(cursor)
            conn.commit()
        finally:
            cursor.close()
    finally:
        conn.close()


if __name__ == "__main__":
    run()
