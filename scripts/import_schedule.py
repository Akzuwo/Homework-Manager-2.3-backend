#!/usr/bin/env python3
"""CLI helper to import class schedules from JSON into the database."""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import sys
from typing import Dict, Iterable, List, Tuple

import mysql.connector


DEFAULT_DB_CONFIG = {
    "host": os.getenv("DB_HOST", "mc-mysql01.mc-host24.de"),
    "user": os.getenv("DB_USER", "u4203_Mtc42FNhxN"),
    "password": os.getenv("DB_PASSWORD", "nA6U=8ecQBe@vli@SKXN9rK9"),
    "database": os.getenv("DB_NAME", "s4203_reports"),
    "port": int(os.getenv("DB_PORT", "3306")),
}

WEEKDAY_ORDER = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]


class ScheduleImportError(RuntimeError):
    """Raised when the import fails for a specific reason."""


def _load_json(path: pathlib.Path) -> Dict[str, List[Dict[str, str]]]:
    with path.open("r", encoding="utf-8") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError as exc:  # pragma: no cover - CLI validation
            raise ScheduleImportError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ScheduleImportError("Schedule root must be an object with weekday keys")

    normalised: Dict[str, List[Dict[str, str]]] = {}
    for day, entries in payload.items():
        if not isinstance(entries, list):
            raise ScheduleImportError(f"Entries for '{day}' must be a list")
        normalised_day = str(day).strip() or day
        prepared: List[Dict[str, str]] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ScheduleImportError(f"Entry #{index + 1} for '{day}' must be an object")
            try:
                start = entry["start"].strip()
                end = entry["end"].strip()
                subject = entry["fach"].strip()
            except KeyError as exc:
                raise ScheduleImportError(f"Entry #{index + 1} for '{day}' is missing {exc.args[0]!r}") from exc
            prepared.append(
                {
                    "start": start,
                    "end": end,
                    "fach": subject,
                    "raum": (entry.get("raum") or "-").strip() or "-",
                }
            )
        normalised[normalised_day] = prepared
    return normalised


def _resolve_class_id(cursor: mysql.connector.cursor.MySQLCursor, identifier: str) -> int:
    identifier = identifier.strip()
    if identifier.isdigit():
        cursor.execute("SELECT id FROM classes WHERE id=%s", (int(identifier),))
    else:
        slug = identifier.lower()
        cursor.execute("SELECT id FROM classes WHERE slug=%s", (slug,))
    row = cursor.fetchone()
    if not row:
        raise ScheduleImportError(f"Class '{identifier}' does not exist")
    return int(row[0])


def _ensure_schedule_metadata(
    conn: mysql.connector.MySQLConnection,
    class_id: int,
    source: str,
    import_hash: str,
    imported_at: _dt.datetime,
) -> None:
    cursor = conn.cursor()
    try:
        cursor.execute("SHOW COLUMNS FROM class_schedules LIKE 'updated_at'")
        has_updated_at = cursor.fetchone() is not None

        cursor.execute("SELECT id FROM class_schedules WHERE class_id=%s", (class_id,))
        row = cursor.fetchone()
        now = _dt.datetime.utcnow()
        if row:
            schedule_id = int(row[0])
            if has_updated_at:
                cursor.execute(
                    "UPDATE class_schedules SET source=%s, import_hash=%s, imported_at=%s, updated_at=%s WHERE id=%s",
                    (source, import_hash, imported_at, now, schedule_id),
                )
            else:
                cursor.execute(
                    "UPDATE class_schedules SET source=%s, import_hash=%s, imported_at=%s WHERE id=%s",
                    (source, import_hash, imported_at, schedule_id),
                )
        else:
            if has_updated_at:
                cursor.execute(
                    """
                    INSERT INTO class_schedules (class_id, source, import_hash, imported_at, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (class_id, source, import_hash, imported_at, now, now),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO class_schedules (class_id, source, import_hash, imported_at, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (class_id, source, import_hash, imported_at, now),
                )
    finally:
        cursor.close()


def _upsert_schedule_entries(
    conn: mysql.connector.MySQLConnection,
    class_id: int,
    schedule: Dict[str, List[Dict[str, str]]],
) -> int:
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM stundenplan_entries WHERE class_id=%s", (class_id,))
        inserted = 0
        ordered_days = WEEKDAY_ORDER + sorted(set(schedule.keys()) - set(WEEKDAY_ORDER))
        for day in ordered_days:
            entries = schedule.get(day)
            if not entries:
                continue
            for entry in entries:
                cursor.execute(
                    """
                    INSERT INTO stundenplan_entries (class_id, tag, start, `end`, fach, raum)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        class_id,
                        day,
                        entry.get("start"),
                        entry.get("end"),
                        entry.get("fach"),
                        entry.get("raum"),
                    ),
                )
                inserted += 1
        return inserted
    finally:
        cursor.close()


def import_schedule(path: pathlib.Path, *, class_identifier: str | None, source: str) -> Tuple[int, str]:
    schedule = _load_json(path)
    payload_bytes = json.dumps(schedule, sort_keys=True, ensure_ascii=False).encode("utf-8")
    import_hash = hashlib.sha256(payload_bytes).hexdigest()
    imported_at = _dt.datetime.utcnow()

    conn = mysql.connector.connect(**DEFAULT_DB_CONFIG)
    try:
        cursor = conn.cursor()
        try:
            identifier = class_identifier or path.stem.replace("stundenplan-", "", 1)
            if not identifier:
                raise ScheduleImportError("Unable to determine class identifier. Use --class.")
            class_id = _resolve_class_id(cursor, identifier)
        finally:
            cursor.close()

        inserted = _upsert_schedule_entries(conn, class_id, schedule)
        _ensure_schedule_metadata(conn, class_id, source, import_hash, imported_at)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return inserted, import_hash


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import class schedules from JSON files")
    parser.add_argument("files", nargs="+", help="Path(s) to stundenplan-<klasse>.json")
    parser.add_argument(
        "--class",
        dest="class_identifier",
        help="Override class identifier (slug or numeric id). Defaults to the value derived from the filename.",
    )
    parser.add_argument(
        "--source",
        default="cli-import",
        help="Source label stored with the class_schedules entry (default: cli-import)",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary: List[Tuple[pathlib.Path, int, str]] = []

    for filename in args.files:
        path = pathlib.Path(filename).expanduser().resolve()
        if not path.is_file():
            raise ScheduleImportError(f"File not found: {path}")
        inserted, import_hash = import_schedule(path, class_identifier=args.class_identifier, source=args.source)
        summary.append((path, inserted, import_hash))

    for path, inserted, import_hash in summary:
        print(f"Imported {inserted} entries from {path.name} (hash={import_hash})")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    try:
        raise SystemExit(main())
    except ScheduleImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
