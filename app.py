import json
import os
import datetime
import re
import time
import smtplib
from collections import OrderedDict
from contextlib import closing
from email.message import EmailMessage
from typing import Dict, Optional, Tuple, Any, Iterable

from ics import Calendar, Event
import pytz
from flask import Flask, jsonify, request, session, make_response, send_from_directory, Response, g
from functools import wraps
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling

from auth.utils import calculate_token_expiry, generate_token, verify_password, hash_password
from class_ids import DEFAULT_ENTRY_CLASS_ID, ENTRY_CLASS_ID_SET

# ---------- APP INITIALISIEREN ----------
app = Flask(__name__, static_url_path="/")

# Session‐Cookies auch cross‐site erlauben
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True
)

# Secrets laden
with open('/etc/secrets/hwm-session-secret', encoding='utf-8') as f:
    app.secret_key = f.read().strip()

# ---------- CORS ----------
CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": [
        "https://*.homework-manager.pages.dev",
        "https://homework-manager.akzuwo.ch",
        "https://hw-manager.akzuwo.ch",
        "https://hwm-beta.akzuwo.ch"
    ]}},
    methods=["GET","HEAD","POST","OPTIONS","PUT","DELETE"],
    allow_headers=["Content-Type"]
)
# ---------- DATABASE POOL ----------
DB_CONFIG = {
    "host":     "mc-mysql01.mc-host24.de",
    "user":     "u4203_Mtc42FNhxN",
    "password": "nA6U=8ecQBe@vli@SKXN9rK9",
    "database": "s4203_reports",
    "port":     3306
}
pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, pool_reset_session=True, **DB_CONFIG)
def get_connection():
    return pool.get_connection()


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value.isoformat(timespec='seconds')
    if isinstance(value, datetime.date):
        return value.isoformat()
    return value


def _serialize_rows(rows: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    serialized = []
    for row in rows:
        serialized.append({key: _serialize_value(value) for key, value in row.items()})
    return serialized


def _parse_pagination(default_size: int = 25, max_size: int = 100) -> Tuple[int, int]:
    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    try:
        page_size = int(request.args.get('page_size', default_size))
    except (TypeError, ValueError):
        page_size = default_size
    if page_size < 1:
        page_size = default_size
    page_size = min(page_size, max_size)
    return page, page_size


def _log_admin_action(conn, action: str, entity_type: str, entity_id: Optional[int] = None, details: Optional[Dict[str, Any]] = None) -> None:
    actor_id = session.get('user_id')
    if not actor_id:
        return

    payload = None
    if details is not None:
        try:
            payload = json.dumps(details, ensure_ascii=False)
        except (TypeError, ValueError):
            payload = None

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO admin_audit_logs (actor_id, action, entity_type, entity_id, details)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (actor_id, action, entity_type, entity_id, payload),
        )
    except mysql.connector.Error:
        app.logger.exception('Failed to write admin audit log')
    finally:
        cursor.close()


def _pagination_response(data: Iterable[Dict[str, Any]], total: int, page: int, page_size: int):
    return jsonify(
        {
            'status': 'ok',
            'data': list(_serialize_rows(data)),
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total,
            },
        }
    )


def _parse_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        value = value.strip().lower()
        if value in {'1', 'true', 'yes', 'on'}:
            return True
        if value in {'0', 'false', 'no', 'off'}:
            return False
    return default


def _ensure_int(value: Any, allow_none: bool = True) -> Optional[int]:
    if value is None:
        return None if allow_none else None
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return None
    return ivalue


DEFAULT_CLASS_SLUG = (os.getenv('DEFAULT_CLASS_SLUG', 'default') or 'default').strip().lower() or 'default'
WEEKDAY_ORDER = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]

CONTACT_MAX_FILE_SIZE = int(os.getenv('CONTACT_MAX_FILE_SIZE', 2 * 1024 * 1024))
CONTACT_RATE_LIMIT = {}
CONTACT_RATE_LIMIT_WINDOW = int(os.getenv('CONTACT_RATE_LIMIT_WINDOW', 3600))
CONTACT_RATE_LIMIT_MAX = int(os.getenv('CONTACT_RATE_LIMIT_MAX', 5))
CONTACT_MIN_DURATION_MS = int(os.getenv('CONTACT_MIN_DURATION_MS', 3000))
CONTACT_MIN_MESSAGE_LENGTH = int(os.getenv('CONTACT_MIN_MESSAGE_LENGTH', 20))
CONTACT_SMTP_HOST = os.getenv('CONTACT_SMTP_HOST')
CONTACT_SMTP_PORT = int(os.getenv('CONTACT_SMTP_PORT', 587))
CONTACT_SMTP_USER = os.getenv('CONTACT_SMTP_USER')
CONTACT_SMTP_PASSWORD = os.getenv('CONTACT_SMTP_PASSWORD')
CONTACT_RECIPIENT = os.getenv('CONTACT_RECIPIENT') or CONTACT_SMTP_USER
CONTACT_FROM_ADDRESS = os.getenv('CONTACT_FROM_ADDRESS', CONTACT_SMTP_USER or CONTACT_RECIPIENT)
CONTACT_EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

PRIMARY_TEST_BASE_URL = os.getenv('PRIMARY_TEST_BASE_URL', 'https://hwm-beta.akzuwo.ch')
LOGIN_RATE_LIMIT = {}
LOGIN_RATE_LIMIT_WINDOW = int(os.getenv('LOGIN_RATE_LIMIT_WINDOW', 300))
LOGIN_RATE_LIMIT_MAX = int(os.getenv('LOGIN_RATE_LIMIT_MAX', 10))
VERIFY_RATE_LIMIT = {}
VERIFY_RATE_LIMIT_WINDOW = int(os.getenv('VERIFY_RATE_LIMIT_WINDOW', 3600))
VERIFY_RATE_LIMIT_MAX = int(os.getenv('VERIFY_RATE_LIMIT_MAX', 5))

EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS = int(os.getenv('EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS', 3600))
EMAIL_VERIFICATION_FROM_ADDRESS = os.getenv('EMAIL_VERIFICATION_FROM_ADDRESS', CONTACT_FROM_ADDRESS or CONTACT_SMTP_USER or CONTACT_RECIPIENT)
EMAIL_VERIFICATION_SUBJECT = os.getenv('EMAIL_VERIFICATION_SUBJECT', 'Bitte E-Mail-Adresse bestätigen')
EMAIL_VERIFICATION_LINK_BASE = os.getenv(
    'EMAIL_VERIFICATION_LINK_BASE',
    f"{PRIMARY_TEST_BASE_URL.rstrip('/')}/verify-email",
)

REGISTRATION_ALLOWED_DOMAIN = os.getenv('REGISTRATION_ALLOWED_DOMAIN', '@sluz.ch').lower()


def require_role(*roles):
    """Decorator to guard endpoints behind role-based access control."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.method == 'OPTIONS':
                return fn(*args, **kwargs)
            current_role = session.get('role')
            if roles:
                allowed = current_role in roles
            else:
                allowed = current_role is not None
            if not allowed:
                return jsonify(status='error', message='Forbidden'), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _get_session_class_id() -> Optional[int]:
    class_id = session.get('class_id')
    try:
        return int(class_id) if class_id is not None else None
    except (TypeError, ValueError):
        return None


def _normalize_entry_class_id(raw_value: Optional[object]) -> str:
    value = (str(raw_value).strip() if raw_value is not None else '').replace(' ', '')
    if not value or value.isdigit() or len(value) < 2:
        return DEFAULT_ENTRY_CLASS_ID

    prefix, suffix = value[:-1], value[-1]
    normalized = f"{prefix.upper()}{suffix.lower()}"
    if normalized not in ENTRY_CLASS_ID_SET:
        raise ValueError('invalid_class_id')
    return normalized


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return fn(*args, **kwargs)
        if not session.get('is_admin'):
            return jsonify(status='error', message='Forbidden'), 403
        return fn(*args, **kwargs)

    return wrapper


def require_class_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return fn(*args, **kwargs)
        if not (session.get('is_admin') or session.get('is_class_admin')):
            return jsonify(status='error', message='Forbidden'), 403
        return fn(*args, **kwargs)

    return wrapper


def require_class_context(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return fn(*args, **kwargs)
        class_id = _get_session_class_id()
        if class_id is None:
            return jsonify(status='error', message='class_required'), 403
        g.active_class_id = class_id
        return fn(*args, **kwargs)

    return wrapper


def _get_request_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        candidate = forwarded_for.split(',')[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or 'unknown'


def _check_rate_limit(bucket, identifier: str, window: int, maximum: int) -> bool:
    now = time.time()
    entry = bucket.get(identifier)
    if entry and now < entry['reset']:
        entry['count'] += 1
    else:
        entry = {'count': 1, 'reset': now + window}
        bucket[identifier] = entry
    return entry['count'] <= maximum


def _check_contact_rate_limit(ip_address: str) -> bool:
    return _check_rate_limit(
        CONTACT_RATE_LIMIT,
        ip_address,
        CONTACT_RATE_LIMIT_WINDOW,
        CONTACT_RATE_LIMIT_MAX,
    )


def _deliver_email(
    to_address: str,
    subject: str,
    body: str,
    *,
    sender: Optional[str] = None,
    reply_to: Optional[str] = None,
    attachment: Optional[Tuple[bytes, str, Optional[str]]] = None,
) -> None:
    if not CONTACT_SMTP_HOST:
        raise RuntimeError('Email delivery is not configured')

    message = EmailMessage()
    message['Subject'] = subject.strip() or 'Homework Manager'
    message['To'] = to_address

    final_sender = sender or CONTACT_FROM_ADDRESS or CONTACT_SMTP_USER or CONTACT_RECIPIENT
    if final_sender:
        message['From'] = final_sender
    if reply_to:
        message['Reply-To'] = reply_to

    message.set_content(body)

    if attachment:
        file_data, filename, content_type = attachment
        if file_data:
            maintype, subtype = (content_type or 'application/octet-stream').split('/', 1)
            message.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=filename)

    server = None
    try:
        if CONTACT_SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(CONTACT_SMTP_HOST, CONTACT_SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(CONTACT_SMTP_HOST, CONTACT_SMTP_PORT, timeout=10)
            server.starttls()

        if CONTACT_SMTP_USER and CONTACT_SMTP_PASSWORD:
            server.login(CONTACT_SMTP_USER, CONTACT_SMTP_PASSWORD)

        server.send_message(message)
    finally:
        if server is not None:
            server.quit()


def _send_contact_email(name: str, email_address: str, subject: str, body: str, attachment=None) -> None:
    if not CONTACT_RECIPIENT:
        raise RuntimeError('Contact email is not configured')

    final_subject = subject.strip() or 'Kontaktanfrage'
    prefixed_subject = f"[Homework Manager] {final_subject}"
    sender = CONTACT_FROM_ADDRESS or email_address or CONTACT_SMTP_USER or CONTACT_RECIPIENT

    _deliver_email(
        CONTACT_RECIPIENT,
        prefixed_subject,
        body,
        sender=sender,
        reply_to=email_address or None,
        attachment=attachment,
    )


def _send_verification_email(email_address: str, token: str, expires_at: datetime.datetime) -> None:
    if not email_address:
        raise ValueError('email_address is required')

    if EMAIL_VERIFICATION_LINK_BASE:
        separator = '&' if '?' in EMAIL_VERIFICATION_LINK_BASE else '?'
        verification_link = f"{EMAIL_VERIFICATION_LINK_BASE}{separator}token={token}"
    else:
        verification_link = token

    expiration_text = expires_at.strftime('%d.%m.%Y %H:%M UTC')
    body = (
        "Hallo,\n\n"
        "bitte bestätige deine E-Mail-Adresse für den Homework Manager über den folgenden Link:\n"
        f"{verification_link}\n\n"
        f"Der Link ist bis {expiration_text} gültig.\n\n"
        "Falls du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail.\n"
    )

    _deliver_email(
        email_address,
        EMAIL_VERIFICATION_SUBJECT,
        body,
        sender=EMAIL_VERIFICATION_FROM_ADDRESS,
    )


def _load_admin_user(conn) -> Optional[Dict[str, object]]:
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, email, password_hash, is_active, email_verified_at, role FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1"
        )
        row = cursor.fetchone()
    finally:
        cursor.close()

    if not row:
        return None

    is_active = row.get('is_active')
    try:
        if is_active is not None and int(is_active) == 0:
            return None
    except (TypeError, ValueError):
        pass

    return row


def _load_user_by_email(conn, email: str) -> Optional[Dict[str, object]]:
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, email, password_hash, role, class_id, is_active, email_verified_at
            FROM users WHERE email=%s LIMIT 1
            """,
            (email,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def _mark_user_login(conn, user_id: int) -> None:
    cursor = conn.cursor()
    try:
        timestamp = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cursor.execute(
            "UPDATE users SET last_login_at=%s WHERE id=%s",
            (timestamp, user_id),
        )
        conn.commit()
    except mysql.connector.Error:
        conn.rollback()
        raise
    finally:
        cursor.close()


def _create_email_verification(conn, user: Dict[str, object]) -> Tuple[str, datetime.datetime]:
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM email_verifications WHERE user_id=%s AND verified_at IS NULL",
            (user['id'],),
        )
        token = generate_token()
        expires_at = calculate_token_expiry(EMAIL_VERIFICATION_TOKEN_LIFETIME_SECONDS)
        cursor.execute(
            "INSERT INTO email_verifications (user_id, email, token, expires_at) VALUES (%s, %s, %s, %s)",
            (user['id'], user['email'], token, expires_at),
        )
        conn.commit()
    except mysql.connector.Error:
        conn.rollback()
        raise
    finally:
        cursor.close()

    try:
        _send_verification_email(user['email'], token, expires_at)
    except Exception as exc:
        raise RuntimeError('verification_email_failed') from exc

    return token, expires_at


def _validate_columns(table_name, columns, requirements):
    missing = [col for col in requirements if col not in columns]
    if missing:
        missing_str = ", ".join(sorted(missing))
        raise RuntimeError(f"Table '{table_name}' is missing columns: {missing_str}. Run database migrations.")
    for column, expected_prefixes in requirements.items():
        definition = (columns.get(column) or "").lower()
        if not any(definition.startswith(prefix) for prefix in expected_prefixes):
            prefixes = ", ".join(expected_prefixes)
            raise RuntimeError(
                f"Column '{column}' in table '{table_name}' has type '{columns.get(column)}', expected prefix one of: {prefixes}."
            )


# Tabelle für den Stundenplan sicherstellen
def ensure_stundenplan_table():
    try:
        conn = get_connection()
    except Exception:
        return
    cur = conn.cursor()
    try:
        cur.execute("SHOW TABLES LIKE 'stundenplan_entries'")
        if cur.fetchone() is None:
            raise RuntimeError("Table 'stundenplan_entries' is missing. Run database migrations.")
        cur.execute("SHOW COLUMNS FROM stundenplan_entries")
        columns = {row[0]: row[1] for row in cur.fetchall()}
        _validate_columns(
            "stundenplan_entries",
            columns,
            {
                "id": ("int",),
                "class_id": ("int",),
                "tag": ("varchar",),
                "start": ("varchar",),
                "end": ("varchar",),
                "fach": ("varchar",),
                "raum": ("varchar",),
            },
        )
    finally:
        cur.close()
        conn.close()


# Tabelle für allgemeine Einträge sicherstellen
def ensure_entries_table():
    try:
        conn = get_connection()
    except Exception:
        return
    cur = conn.cursor()
    try:
        cur.execute("SHOW TABLES LIKE 'eintraege'")
        if cur.fetchone() is None:
            raise RuntimeError("Table 'eintraege' is missing. Run database migrations.")
        cur.execute("SHOW COLUMNS FROM eintraege")
        columns = {row[0]: row[1] for row in cur.fetchall()}
        _validate_columns(
            "eintraege",
            columns,
            {
                "id": ("int",),
                "class_id": ("varchar",),
                "beschreibung": ("text",),
                "datum": ("date",),
                "startzeit": ("time",),
                "endzeit": ("time",),
                "typ": ("enum",),
                "fach": ("varchar",),
            },
        )
    finally:
        cur.close()
        conn.close()


ensure_stundenplan_table()
ensure_entries_table()

# ---- Klassen- und Stundenplanhilfen ----

def _resolve_class_id(raw_identifier, conn=None):
    owns_connection = conn is None
    if owns_connection:
        conn = get_connection()
    cursor = conn.cursor()
    try:
        identifier = (raw_identifier or "").strip()
        if not identifier:
            cursor.execute("SELECT id FROM classes WHERE slug=%s", (DEFAULT_CLASS_SLUG,))
        elif identifier.isdigit():
            cursor.execute("SELECT id FROM classes WHERE id=%s", (int(identifier),))
        else:
            cursor.execute("SELECT id FROM classes WHERE slug=%s", (identifier.lower(),))
        row = cursor.fetchone()
    finally:
        cursor.close()
        if owns_connection and conn is not None:
            conn.close()
    if not row:
        raise ValueError("class_not_found")
    return int(row[0])


def _normalize_schedule_rows(rows):
    normalized = []
    for row in rows:
        normalized.append(
            {
                "start": row.get("start"),
                "end": row.get("end"),
                "fach": row.get("fach"),
                "raum": row.get("raum") or "-",
            }
        )
    return normalized


def _load_schedule_for_class(conn, class_id):
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT tag, start, `end`, fach, raum FROM stundenplan_entries WHERE class_id=%s ORDER BY tag, start",
            (class_id,),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()

    schedule_map = {day: [] for day in WEEKDAY_ORDER}
    extra_days = {}
    for row in rows:
        entry = {
            "start": row.get("start"),
            "end": row.get("end"),
            "fach": row.get("fach"),
            "raum": row.get("raum") or "-",
        }
        day = row.get("tag")
        if day in schedule_map:
            schedule_map[day].append(entry)
        else:
            extra_days.setdefault(day, []).append(entry)

    ordered = OrderedDict()
    for day in WEEKDAY_ORDER:
        entries = schedule_map[day]
        entries.sort(key=lambda item: item.get("start") or "")
        ordered[day] = entries
    for day in sorted(extra_days):
        entries = extra_days[day]
        entries.sort(key=lambda item: item.get("start") or "")
        ordered[day] = entries
    return ordered


def _load_schedule_for_day(conn, class_id, weekday):
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT start, `end`, fach, raum FROM stundenplan_entries WHERE class_id=%s AND tag=%s ORDER BY start",
            (class_id, weekday),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    return _normalize_schedule_rows(rows)


# Hilfsfunktion für die Formatierung von Zeitwerten aus MySQL
def _format_time_value(value):
    if value is None:
        return None
    if isinstance(value, datetime.timedelta):
        total_seconds = int(value.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    if isinstance(value, datetime.datetime):
        return value.time().strftime('%H:%M:%S')
    if isinstance(value, datetime.time):
        return value.strftime('%H:%M:%S')
    if isinstance(value, str):
        return value
    return str(value)

# ---------- ROUTES ----------

@app.route("/")
def root():
    return send_from_directory(app.static_folder, "login.html")

@app.route('/calendar.ics')
@require_class_context
def export_ics():
    """Erzeugt eine iCalendar-Datei mit allen zukünftigen Einträgen."""
    class_id = g.get('active_class_id') or _get_session_class_id()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, typ, beschreibung, datum, fach
        FROM eintraege
        WHERE class_id=%s AND datum >= CURDATE()
        ORDER BY datum ASC
        """,
        (class_id,),
    )
    entries = cursor.fetchall()
    cursor.close()
    conn.close()

    cal = Calendar()
    for e in entries:
        due = e['datum']
        ev = Event()
        subject = e.get('fach', '').strip()
        typ_label = e['typ'].capitalize()
        title_parts = [typ_label]
        if subject:
            title_parts.append(subject)
        ev.name = " - ".join(title_parts)
        ev.description = e['beschreibung']
        ev.begin = due
        ev.make_all_day()
        ev.uid = f"eintrag-{e['id']}@homework-manager.akzuwo.ch"
        cal.events.add(ev)

    ics_text = str(cal)
    return Response(
        ics_text,
        mimetype='text/calendar',
        headers={'Content-Disposition': 'attachment; filename="homework.ics"'}
    )

@app.route('/entries')
@require_class_context
def entries():
    """Gibt alle Einträge zurück."""
    class_id = g.get('active_class_id') or _get_session_class_id()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, beschreibung, datum, startzeit, endzeit, typ, fach
        FROM eintraege
        WHERE class_id=%s
        ORDER BY datum ASC, startzeit ASC
        """,
        (class_id,),
    )
    rows = cursor.fetchall()
    for r in rows:
        r['datum'] = r['datum'].strftime('%Y-%m-%d')
        r['startzeit'] = _format_time_value(r.get('startzeit'))
        r['endzeit'] = _format_time_value(r.get('endzeit'))
    cursor.close()
    conn.close()
    return jsonify(rows)


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    form = request.form
    honeypot = form.get('hm_contact_website')
    if honeypot:
        return jsonify({'status': 'ok'}), 200

    name = (form.get('name') or '').strip()
    email_address = (form.get('email') or '').strip()
    subject = (form.get('subject') or '').strip()
    message_text = (form.get('message') or '').strip()
    consent_given = form.get('consent') in ('true', 'on', '1')
    started_raw = form.get('hm-contact-start')

    errors = {}

    if not name:
        errors['name'] = 'required'
    if not email_address or not CONTACT_EMAIL_REGEX.match(email_address):
        errors['email'] = 'invalid'
    if not subject:
        errors['subject'] = 'required'
    if len(message_text) < CONTACT_MIN_MESSAGE_LENGTH:
        errors['message'] = 'too_short'
    if not consent_given:
        errors['consent'] = 'required'

    try:
        started_ms = int(started_raw) if started_raw else 0
    except ValueError:
        started_ms = 0

    if started_ms:
        elapsed = (time.time() * 1000) - started_ms
        if elapsed < CONTACT_MIN_DURATION_MS:
            errors['general'] = 'too_fast'

    attachment_tuple = None
    uploaded_file = request.files.get('attachment')
    if uploaded_file and uploaded_file.filename:
        try:
            uploaded_file.stream.seek(0, os.SEEK_END)
            size = uploaded_file.stream.tell()
            uploaded_file.stream.seek(0)
        except Exception:
            size = None
        if size and size > CONTACT_MAX_FILE_SIZE:
            return jsonify({'message': 'attachment_too_large'}), 413
        file_data = uploaded_file.read()
        if file_data and len(file_data) > CONTACT_MAX_FILE_SIZE:
            return jsonify({'message': 'attachment_too_large'}), 413
        if file_data:
            attachment_tuple = (file_data, uploaded_file.filename, uploaded_file.mimetype)

    if errors:
        return jsonify({'message': 'invalid', 'errors': errors}), 400

    if not (CONTACT_SMTP_HOST and CONTACT_RECIPIENT):
        return jsonify({'message': 'unavailable'}), 503

    ip_address = _get_request_ip()

    if not _check_contact_rate_limit(ip_address):
        return jsonify({'message': 'rate_limited'}), 429

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    body = (
        f"Name: {name}\n"
        f"E-Mail: {email_address}\n"
        f"Betreff: {subject or '-'}\n"
        f"Einwilligung: {'ja' if consent_given else 'nein'}\n"
        f"IP-Adresse: {ip_address}\n"
        f"Zeitstempel: {timestamp}\n\n"
        f"Nachricht:\n{message_text.strip()}\n"
    )

    try:
        _send_contact_email(name, email_address, subject, body, attachment_tuple)
    except Exception as exc:
        app.logger.exception('Fehler beim Versenden der Kontaktanfrage: %s', exc)
        return jsonify({'message': 'send_failed'}), 502

    return jsonify({'status': 'ok'}), 200

# --- AUTHENTICATION ---
@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    class_identifier = data.get('class')

    errors = {}
    if not email or '@' not in email or not email.endswith(REGISTRATION_ALLOWED_DOMAIN):
        errors['email'] = 'invalid_email'
    if not password or len(password) < 8:
        errors['password'] = 'weak_password'

    if errors:
        return jsonify(status='error', errors=errors), 400

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        try:
            existing = _load_user_by_email(conn, email)
        except mysql.connector.Error:
            app.logger.exception('Failed to check existing user for registration')
            return jsonify(status='error', message='database_unavailable'), 503

        if existing:
            return jsonify(status='error', message='email_exists'), 409

        class_id = None
        if class_identifier is not None:
            try:
                class_id = _resolve_class_id(class_identifier, conn=conn)
            except ValueError:
                return jsonify(status='error', message='class_not_found'), 404
        else:
            try:
                class_id = _resolve_class_id(DEFAULT_CLASS_SLUG, conn=conn)
            except Exception:
                class_id = None

        password_hash_value = hash_password(password)

        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, password_hash, role, class_id, is_active, email_verified_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (email, password_hash_value, 'student', class_id, 1, None),
            )
            user_id = cursor.lastrowid
            conn.commit()
        except mysql.connector.Error:
            conn.rollback()
            app.logger.exception('Failed to create user during registration')
            return jsonify(status='error', message='registration_failed'), 500
        finally:
            cursor.close()

        user = {'id': user_id, 'email': email, 'role': 'student'}
        try:
            _create_email_verification(conn, user)
        except mysql.connector.Error:
            app.logger.exception('Failed to create verification token for user %s', user)
            return jsonify(status='error', message='verification_failed'), 500
        except RuntimeError:
            return jsonify(status='error', message='mail_failed'), 502

    return jsonify(status='ok')


@app.route('/api/auth/login', methods=['POST'])
@app.route('/api/login', methods=['POST'])
def auth_login():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()

    if not email or not password:
        return jsonify(status='error', message='invalid_credentials'), 401

    ip_address = _get_request_ip()
    if not _check_rate_limit(
        LOGIN_RATE_LIMIT,
        ip_address,
        LOGIN_RATE_LIMIT_WINDOW,
        LOGIN_RATE_LIMIT_MAX,
    ):
        return jsonify(status='error', message='rate_limited'), 429

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        try:
            user = _load_user_by_email(conn, email)
        except mysql.connector.Error:
            app.logger.exception('Failed to load user for login')
            return jsonify(status='error', message='database_unavailable'), 503

        if not user:
            return jsonify(status='error', message='invalid_credentials'), 401

        if not verify_password(user.get('password_hash'), password):
            return jsonify(status='error', message='invalid_credentials'), 401

        try:
            if user.get('is_active') is not None and int(user['is_active']) == 0:
                return jsonify(status='error', message='inactive'), 403
        except (TypeError, ValueError):
            pass

        if not user.get('email_verified_at'):
            return jsonify(status='error', message='email_not_verified'), 403

        session['user_id'] = int(user['id'])
        role = (user.get('role') or 'student').strip() or 'student'
        session['role'] = role
        class_id_value = user.get('class_id')
        if class_id_value is None:
            session.pop('class_id', None)
        else:
            try:
                session['class_id'] = int(class_id_value)
            except (TypeError, ValueError):
                session.pop('class_id', None)
        is_admin = role == 'admin'
        session['is_admin'] = is_admin
        session['is_class_admin'] = bool(is_admin or role == 'teacher')

        try:
            _mark_user_login(conn, int(user['id']))
        except (mysql.connector.Error, KeyError, ValueError):
            app.logger.exception('Failed to update last login for user %s', user)

    LOGIN_RATE_LIMIT.pop(ip_address, None)
    return jsonify(status='ok', role=session.get('role'))


@app.route('/api/auth/logout', methods=['POST'])
@app.route('/api/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify(status='ok')


@app.route('/api/auth/verify', methods=['POST'])
def auth_verify():
    data = request.json or {}
    token = (data.get('token') or request.args.get('token') or '').strip()

    if not token:
        return jsonify(status='error', message='token_required'), 400

    ip_address = _get_request_ip()
    if not _check_rate_limit(
        VERIFY_RATE_LIMIT,
        ip_address,
        VERIFY_RATE_LIMIT_WINDOW,
        VERIFY_RATE_LIMIT_MAX,
    ):
        return jsonify(status='error', message='rate_limited'), 429

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    with closing(conn):
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT ev.id, ev.user_id, ev.token, ev.expires_at, ev.verified_at, u.email_verified_at
                FROM email_verifications ev
                JOIN users u ON u.id = ev.user_id
                WHERE ev.token=%s
                LIMIT 1
                """,
                (token,),
            )
            verification = cursor.fetchone()
        except mysql.connector.Error:
            cursor.close()
            return jsonify(status='error', message='database_unavailable'), 503

        if not verification:
            cursor.close()
            return jsonify(status='error', message='invalid_token'), 404

        expires_at = verification.get('expires_at')
        verified_at = verification.get('verified_at')
        user_verified_at = verification.get('email_verified_at')

        if verified_at or user_verified_at:
            cursor.close()
            return jsonify(status='error', message='already_verified'), 409

        if expires_at and expires_at < now:
            cursor.close()
            return jsonify(status='error', message='token_expired'), 410

        cursor.close()

        update_cursor = conn.cursor()
        try:
            update_cursor.execute(
                "UPDATE users SET email_verified_at=%s WHERE id=%s",
                (now, int(verification['user_id'])),
            )
            update_cursor.execute(
                "UPDATE email_verifications SET verified_at=%s WHERE id=%s",
                (now, int(verification['id'])),
            )
            conn.commit()
        except mysql.connector.Error:
            conn.rollback()
            update_cursor.close()
            return jsonify(status='error', message='verification_failed'), 500
        finally:
            update_cursor.close()

    VERIFY_RATE_LIMIT.pop(ip_address, None)
    return jsonify(status='ok')


@app.route('/api/auth/resend', methods=['POST'])
def auth_resend():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()

    if not email:
        return jsonify(status='error', message='email_required'), 400

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        try:
            user = _load_user_by_email(conn, email)
        except mysql.connector.Error:
            app.logger.exception('Failed to load user for resend %s', email)
            return jsonify(status='error', message='database_unavailable'), 503

        if not user:
            return jsonify(status='error', message='user_not_found'), 404

        if user.get('email_verified_at'):
            return jsonify(status='error', message='already_verified'), 409

        try:
            _create_email_verification(conn, user)
        except mysql.connector.Error:
            app.logger.exception('Failed to create verification token for user %s', user)
            return jsonify(status='error', message='verification_failed'), 500
        except RuntimeError:
            return jsonify(status='error', message='mail_failed'), 502

    return jsonify(status='ok')


@app.route('/api/auth/password-reset', methods=['POST'])
def auth_password_reset():
    return jsonify(status='error', message='not_implemented'), 501


@app.route('/api/admin/resend-verification', methods=['POST'])
@require_role('admin')
def resend_admin_verification():
    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        try:
            admin_user = _load_admin_user(conn)
        except mysql.connector.Error:
            app.logger.exception('Failed to load admin user for verification')
            return jsonify(status='error', message='database_unavailable'), 503

        if not admin_user:
            return jsonify(status='error', message='admin_not_found'), 404

        if admin_user.get('email_verified_at'):
            return jsonify(status='error', message='already_verified'), 409

        try:
            _create_email_verification(conn, admin_user)
        except mysql.connector.Error:
            app.logger.exception('Failed to create verification token for admin %s', admin_user)
            return jsonify(status='error', message='verification_failed'), 500
        except RuntimeError:
            return jsonify(status='error', message='mail_failed'), 502

    return jsonify(status='ok')


@app.route('/api/admin/users', methods=['GET', 'POST', 'OPTIONS'])
@require_role('admin')
def admin_users_collection():
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        if request.method == 'GET':
            page, page_size = _parse_pagination()
            offset = (page - 1) * page_size
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT COUNT(*) AS total FROM users")
                total_row = cursor.fetchone() or {'total': 0}
                total = int(total_row.get('total') or 0)
                cursor.execute(
                    """
                    SELECT id, email, role, class_id, is_active, created_at, updated_at
                    FROM users
                    ORDER BY id DESC
                    LIMIT %s OFFSET %s
                    """,
                    (page_size, offset),
                )
                data = cursor.fetchall() or []
            except mysql.connector.Error:
                return jsonify(status='error', message='database_unavailable'), 503
            finally:
                cursor.close()
            return _pagination_response(data, total, page, page_size)

        data = request.json or {}
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')
        role = (data.get('role') or 'student').strip().lower() or 'student'
        class_id = _ensure_int(data.get('class_id'))
        is_active = _parse_bool(data.get('is_active'), True)

        if not email or '@' not in email:
            return jsonify(status='error', message='invalid_email'), 400
        if role not in {'student', 'teacher', 'admin'}:
            return jsonify(status='error', message='invalid_role'), 400
        if not password:
            return jsonify(status='error', message='password_required'), 400

        password_hash = hash_password(password)
        now = datetime.datetime.utcnow()

        cursor = conn.cursor()
        try:
            if class_id:
                cursor.execute("SELECT id FROM classes WHERE id=%s", (class_id,))
                if cursor.fetchone() is None:
                    return jsonify(status='error', message='class_not_found'), 404
                cursor.close()
                cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO users (email, password_hash, role, class_id, is_active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (email, password_hash, role, class_id, int(is_active), now, now),
            )
            user_id = cursor.lastrowid
            _log_admin_action(
                conn,
                'create',
                'user',
                user_id,
                {'email': email, 'role': role, 'class_id': class_id, 'is_active': bool(is_active)},
            )
            conn.commit()
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='duplicate_email'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()

    return jsonify(status='ok', id=user_id)


@app.route('/api/admin/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@require_role('admin')
def admin_users_resource(user_id: int):
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        cursor = conn.cursor(dictionary=True)
        try:
            if request.method == 'GET':
                cursor.execute(
                    """
                    SELECT id, email, role, class_id, is_active, created_at, updated_at
                    FROM users
                    WHERE id=%s
                    LIMIT 1
                    """,
                    (user_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify(status='error', message='user_not_found'), 404
                return jsonify(status='ok', data=list(_serialize_rows([row]))[0])

            if request.method == 'DELETE':
                cursor.close()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                if cursor.rowcount == 0:
                    return jsonify(status='error', message='user_not_found'), 404
                _log_admin_action(conn, 'delete', 'user', user_id, {})
                conn.commit()
                return jsonify(status='ok')

            data = request.json or {}
            updates = []
            values = []

            if 'email' in data:
                email = (data.get('email') or '').strip().lower()
                if not email or '@' not in email:
                    return jsonify(status='error', message='invalid_email'), 400
                updates.append('email=%s')
                values.append(email)

            role_value = None
            if 'role' in data:
                role_value = (data.get('role') or '').strip().lower()
                if role_value not in {'student', 'teacher', 'admin'}:
                    return jsonify(status='error', message='invalid_role'), 400
                updates.append('role=%s')
                values.append(role_value)

            class_value = None
            if 'class_id' in data:
                class_value = _ensure_int(data.get('class_id'))
                if class_value is not None and class_value <= 0:
                    return jsonify(status='error', message='invalid_class_id'), 400
                if class_value:
                    cursor.execute("SELECT id FROM classes WHERE id=%s", (class_value,))
                    if cursor.fetchone() is None:
                        return jsonify(status='error', message='class_not_found'), 404
                    cursor.close()
                    cursor = conn.cursor(dictionary=True)
                updates.append('class_id=%s')
                values.append(class_value)

            active_value = None
            if 'is_active' in data:
                active_value = _parse_bool(data.get('is_active'), True)
                updates.append('is_active=%s')
                values.append(int(active_value))

            if 'password' in data:
                password = data.get('password')
                if not password:
                    return jsonify(status='error', message='password_required'), 400
                updates.append('password_hash=%s')
                values.append(hash_password(password))

            if not updates:
                return jsonify(status='error', message='no_changes'), 400

            cursor.close()
            cursor = conn.cursor()
            query = f"UPDATE users SET {', '.join(updates)} WHERE id=%s"
            values.append(user_id)
            cursor.execute(query, tuple(values))
            if cursor.rowcount == 0:
                return jsonify(status='error', message='user_not_found'), 404
            _log_admin_action(
                conn,
                'update',
                'user',
                user_id,
                {
                    key: value
                    for key, value in [
                        ('email', data.get('email') if 'email' in data else None),
                        ('role', role_value),
                        ('class_id', class_value),
                        ('is_active', active_value),
                    ]
                    if value is not None
                },
            )
            conn.commit()
            return jsonify(status='ok')
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='duplicate_email'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()


@app.route('/api/secure-data')
@require_admin
def secure_data():
    return jsonify(status='ok', data='Hier sind geheime Daten!')


@app.route('/api/admin/classes', methods=['GET', 'POST', 'OPTIONS'])
@require_role('admin')
def admin_classes_collection():
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        if request.method == 'GET':
            page, page_size = _parse_pagination()
            offset = (page - 1) * page_size
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT COUNT(*) AS total FROM classes")
                total = int((cursor.fetchone() or {'total': 0}).get('total') or 0)
                cursor.execute(
                    """
                    SELECT id, slug, title, description, is_active, created_at, updated_at
                    FROM classes
                    ORDER BY title ASC
                    LIMIT %s OFFSET %s
                    """,
                    (page_size, offset),
                )
                rows = cursor.fetchall() or []
            except mysql.connector.Error:
                return jsonify(status='error', message='database_unavailable'), 503
            finally:
                cursor.close()
            return _pagination_response(rows, total, page, page_size)

        data = request.json or {}
        slug = (data.get('slug') or '').strip().lower()
        title = (data.get('title') or '').strip()
        description = (data.get('description') or '').strip() or None
        is_active = _parse_bool(data.get('is_active'), True)

        if not slug or not re.match(r'^[a-z0-9\-]+$', slug):
            return jsonify(status='error', message='invalid_slug'), 400
        if not title:
            return jsonify(status='error', message='title_required'), 400

        now = datetime.datetime.utcnow()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO classes (slug, title, description, is_active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (slug, title, description, int(is_active), now, now),
            )
            class_id = cursor.lastrowid
            _log_admin_action(
                conn,
                'create',
                'class',
                class_id,
                {'slug': slug, 'title': title, 'is_active': bool(is_active)},
            )
            conn.commit()
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='duplicate_class'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()

    return jsonify(status='ok', id=class_id)


@app.route('/api/admin/classes/<int:class_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@require_role('admin')
def admin_classes_resource(class_id: int):
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        cursor = conn.cursor(dictionary=True)
        try:
            if request.method == 'GET':
                cursor.execute(
                    """
                    SELECT id, slug, title, description, is_active, created_at, updated_at
                    FROM classes
                    WHERE id=%s
                    LIMIT 1
                    """,
                    (class_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify(status='error', message='class_not_found'), 404
                return jsonify(status='ok', data=list(_serialize_rows([row]))[0])

            if request.method == 'DELETE':
                cursor.close()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM classes WHERE id=%s", (class_id,))
                if cursor.rowcount == 0:
                    return jsonify(status='error', message='class_not_found'), 404
                _log_admin_action(conn, 'delete', 'class', class_id, {})
                conn.commit()
                return jsonify(status='ok')

            data = request.json or {}
            updates = []
            values = []

            if 'slug' in data:
                slug = (data.get('slug') or '').strip().lower()
                if not slug or not re.match(r'^[a-z0-9\-]+$', slug):
                    return jsonify(status='error', message='invalid_slug'), 400
                updates.append('slug=%s')
                values.append(slug)

            title_value = None
            if 'title' in data:
                title_value = (data.get('title') or '').strip()
                if not title_value:
                    return jsonify(status='error', message='title_required'), 400
                updates.append('title=%s')
                values.append(title_value)

            if 'description' in data:
                description_value = (data.get('description') or '').strip() or None
                updates.append('description=%s')
                values.append(description_value)

            active_value = None
            if 'is_active' in data:
                active_value = _parse_bool(data.get('is_active'), True)
                updates.append('is_active=%s')
                values.append(int(active_value))

            if not updates:
                return jsonify(status='error', message='no_changes'), 400

            cursor.close()
            cursor = conn.cursor()
            query = f"UPDATE classes SET {', '.join(updates)} WHERE id=%s"
            values.append(class_id)
            cursor.execute(query, tuple(values))
            if cursor.rowcount == 0:
                return jsonify(status='error', message='class_not_found'), 404
            _log_admin_action(
                conn,
                'update',
                'class',
                class_id,
                {
                    key: value
                    for key, value in [
                        ('slug', data.get('slug') if 'slug' in data else None),
                        ('title', title_value),
                        ('description', data.get('description') if 'description' in data else None),
                        ('is_active', active_value),
                    ]
                    if value is not None
                },
            )
            conn.commit()
            return jsonify(status='ok')
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='duplicate_class'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()


@app.route('/api/admin/schedules', methods=['GET', 'POST', 'OPTIONS'])
@require_role('admin')
def admin_schedules_collection():
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        if request.method == 'GET':
            page, page_size = _parse_pagination()
            offset = (page - 1) * page_size
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT COUNT(*) AS total FROM class_schedules")
                total = int((cursor.fetchone() or {'total': 0}).get('total') or 0)
                cursor.execute(
                    """
                    SELECT cs.id, cs.class_id, cs.source, cs.import_hash, cs.imported_at,
                           cs.created_at, cs.updated_at, c.slug AS class_slug, c.title AS class_title
                    FROM class_schedules cs
                    LEFT JOIN classes c ON c.id = cs.class_id
                    ORDER BY cs.id DESC
                    LIMIT %s OFFSET %s
                    """,
                    (page_size, offset),
                )
                rows = cursor.fetchall() or []
            except mysql.connector.Error:
                return jsonify(status='error', message='database_unavailable'), 503
            finally:
                cursor.close()
            return _pagination_response(rows, total, page, page_size)

        data = request.json or {}
        class_id = _ensure_int(data.get('class_id'), allow_none=False)
        if not class_id or class_id <= 0:
            return jsonify(status='error', message='invalid_class_id'), 400

        source = (data.get('source') or '').strip() or None
        import_hash = (data.get('import_hash') or '').strip() or None
        imported_at_raw = data.get('imported_at')
        imported_at = None
        if imported_at_raw:
            try:
                imported_at = datetime.datetime.fromisoformat(imported_at_raw)
            except (TypeError, ValueError):
                return jsonify(status='error', message='invalid_imported_at'), 400

        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM classes WHERE id=%s", (class_id,))
            if cursor.fetchone() is None:
                return jsonify(status='error', message='class_not_found'), 404
            cursor.close()
            cursor = conn.cursor()
            now = datetime.datetime.utcnow()
            cursor.execute(
                """
                INSERT INTO class_schedules (class_id, source, import_hash, imported_at, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (class_id, source, import_hash, imported_at, now, now),
            )
            schedule_id = cursor.lastrowid
            _log_admin_action(
                conn,
                'create',
                'schedule',
                schedule_id,
                {'class_id': class_id, 'source': source, 'import_hash': import_hash},
            )
            conn.commit()
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='schedule_exists'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()

    return jsonify(status='ok', id=schedule_id)


@app.route('/api/admin/schedules/<int:schedule_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@require_role('admin')
def admin_schedules_resource(schedule_id: int):
    if request.method == 'OPTIONS':
        return _cors_preflight()

    try:
        conn = get_connection()
    except Exception:
        return jsonify(status='error', message='database_unavailable'), 503

    with closing(conn):
        cursor = conn.cursor(dictionary=True)
        try:
            if request.method == 'GET':
                cursor.execute(
                    """
                    SELECT cs.id, cs.class_id, cs.source, cs.import_hash, cs.imported_at,
                           cs.created_at, cs.updated_at, c.slug AS class_slug, c.title AS class_title
                    FROM class_schedules cs
                    LEFT JOIN classes c ON c.id = cs.class_id
                    WHERE cs.id=%s
                    LIMIT 1
                    """,
                    (schedule_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify(status='error', message='schedule_not_found'), 404
                return jsonify(status='ok', data=list(_serialize_rows([row]))[0])

            if request.method == 'DELETE':
                cursor.close()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM class_schedules WHERE id=%s", (schedule_id,))
                if cursor.rowcount == 0:
                    return jsonify(status='error', message='schedule_not_found'), 404
                _log_admin_action(conn, 'delete', 'schedule', schedule_id, {})
                conn.commit()
                return jsonify(status='ok')

            data = request.json or {}
            updates = []
            values = []

            class_value = None
            if 'class_id' in data:
                class_value = _ensure_int(data.get('class_id'), allow_none=False)
                if not class_value or class_value <= 0:
                    return jsonify(status='error', message='invalid_class_id'), 400
                cursor.execute("SELECT id FROM classes WHERE id=%s", (class_value,))
                if cursor.fetchone() is None:
                    return jsonify(status='error', message='class_not_found'), 404
                updates.append('class_id=%s')
                values.append(class_value)

            source_value = None
            if 'source' in data:
                source_value = (data.get('source') or '').strip() or None
                updates.append('source=%s')
                values.append(source_value)

            import_hash_value = None
            if 'import_hash' in data:
                import_hash_value = (data.get('import_hash') or '').strip() or None
                updates.append('import_hash=%s')
                values.append(import_hash_value)

            imported_at_value = None
            if 'imported_at' in data:
                imported_raw = data.get('imported_at')
                if imported_raw:
                    try:
                        imported_at_value = datetime.datetime.fromisoformat(imported_raw)
                    except (TypeError, ValueError):
                        return jsonify(status='error', message='invalid_imported_at'), 400
                updates.append('imported_at=%s')
                values.append(imported_at_value)

            if not updates:
                return jsonify(status='error', message='no_changes'), 400

            cursor.close()
            cursor = conn.cursor()
            query = f"UPDATE class_schedules SET {', '.join(updates)} WHERE id=%s"
            values.append(schedule_id)
            cursor.execute(query, tuple(values))
            if cursor.rowcount == 0:
                return jsonify(status='error', message='schedule_not_found'), 404
            _log_admin_action(
                conn,
                'update',
                'schedule',
                schedule_id,
                {
                    key: value
                    for key, value in [
                        ('class_id', class_value),
                        ('source', source_value),
                        ('import_hash', import_hash_value),
                        ('imported_at', imported_at_value),
                    ]
                    if value is not None
                },
            )
            conn.commit()
            return jsonify(status='ok')
        except mysql.connector.Error as exc:
            conn.rollback()
            if getattr(exc, 'errno', None) == mysql.connector.errorcode.ER_DUP_ENTRY:
                return jsonify(status='error', message='schedule_exists'), 409
            return jsonify(status='error', message='database_unavailable'), 503
        finally:
            cursor.close()

@app.route('/api/classes', methods=['GET'])
@require_class_admin
def list_classes():
    is_admin = bool(session.get('is_admin'))
    class_id = _get_session_class_id()
    if not is_admin and class_id is None:
        return jsonify({'status': 'error', 'message': 'class_required'}), 403

    try:
        conn = get_connection()
    except Exception:
        return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503

    with closing(conn):
        cursor = conn.cursor(dictionary=True)
        try:
            if is_admin:
                cursor.execute(
                    "SELECT id, slug, title, description, is_active FROM classes ORDER BY title ASC"
                )
            else:
                cursor.execute(
                    "SELECT id, slug, title, description, is_active FROM classes WHERE id=%s",
                    (class_id,),
                )
            rows = cursor.fetchall() or []
        except mysql.connector.Error:
            return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
        finally:
            cursor.close()

    return jsonify(rows)


@app.route('/api/users/<int:user_id>/class', methods=['PUT', 'OPTIONS'])
@require_class_admin
def assign_user_to_class(user_id: int):
    if request.method == 'OPTIONS':
        return _cors_preflight()

    data = request.json or {}
    target_class_id = data.get('class_id')
    try:
        target_class_id = int(target_class_id)
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'invalid_class_id'}), 400

    if target_class_id <= 0:
        return jsonify({'status': 'error', 'message': 'invalid_class_id'}), 400

    is_admin = bool(session.get('is_admin'))
    acting_class_id = _get_session_class_id()
    if not is_admin and acting_class_id != target_class_id:
        return jsonify({'status': 'error', 'message': 'forbidden'}), 403

    try:
        conn = get_connection()
    except Exception:
        return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503

    with closing(conn):
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM classes WHERE id=%s", (target_class_id,))
            if cursor.fetchone() is None:
                return jsonify({'status': 'error', 'message': 'class_not_found'}), 404

            cursor.execute("SELECT id FROM users WHERE id=%s", (user_id,))
            if cursor.fetchone() is None:
                return jsonify({'status': 'error', 'message': 'user_not_found'}), 404

            cursor.execute(
                "UPDATE users SET class_id=%s WHERE id=%s",
                (target_class_id, user_id),
            )
            conn.commit()
        except mysql.connector.Error:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
        finally:
            cursor.close()

    return jsonify({'status': 'ok'})


# --- UPDATE ENTRY ---
@app.route('/update_entry', methods=['OPTIONS', 'PUT'])
@require_class_admin
@require_class_context
def update_entry():
    if request.method == 'OPTIONS':
        return _cors_preflight()

    data = request.json or {}
    try:
        class_id = _normalize_entry_class_id(data.get('class_id'))
    except ValueError:
        return jsonify(status='error', message='invalid_class_id'), 400

    id = data.get('id')
    desc = (data.get('description') or '').strip()
    date = data.get('date')
    start = data.get('startzeit') or None
    end = data.get('endzeit') or None
    typ = data.get('type')
    fach = (data.get('fach') or '').strip()

    if start:
        start = start.strip()
        if len(start) == 5:
            start = f"{start}:00"
        start = start[:8]
    if end:
        end = end.strip()
        if len(end) == 5:
            end = f"{end}:00"
        end = end[:8]

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT fach FROM eintraege WHERE id=%s AND class_id=%s",
            (id, class_id),
        )
        row = cur.fetchone()
        if not row:
            return jsonify(status='error', message='Eintrag nicht gefunden'), 404

        existing_fach = (row[0] or '').strip()

        if typ != 'event' and not fach and existing_fach:
            return jsonify(status='error', message='fach ist für diesen Typ erforderlich'), 400
        if typ == 'event' and not fach:
            fach = ''

        cur.execute(
            """
            UPDATE eintraege
            SET beschreibung=%s, datum=%s, startzeit=%s, endzeit=%s, typ=%s, fach=%s
            WHERE id=%s AND class_id=%s
            """,
            (desc, date, start, end, typ, fach, id, class_id)
        )
        conn.commit()
        return jsonify(status='ok')
    except Exception as e:
        conn.rollback()
        return jsonify(status='error', message=str(e)), 500
    finally:
        cur.close()
        conn.close()

# --- DELETE ENTRY ---
@app.route('/delete_entry/<int:id>', methods=['DELETE', 'OPTIONS'])
@require_class_admin
@require_class_context
def delete_entry(id):
    # Auth via Session-Cookie (handled by decorator)
    if request.method == 'OPTIONS':
        return _cors_preflight()

    raw_class_id = request.args.get('class_id')
    if raw_class_id is None:
        raw_class_id = g.get('active_class_id') or _get_session_class_id()
    try:
        class_id = _normalize_entry_class_id(raw_class_id)
    except ValueError:
        return jsonify(status='error', message='invalid_class_id'), 400
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM eintraege WHERE id=%s AND class_id=%s",
            (id, class_id),
        )
        conn.commit()
        return jsonify(status='ok')
    except Exception as e:
        return jsonify(status='error', message=str(e)), 500
    finally:
        cur.close()
        conn.close()

# CORS‐Preflight‐Helper
def _cors_preflight():
    resp = make_response()
    resp.headers.update({
        'Access-Control-Allow-Origin':  request.headers.get('Origin', '*'),
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true'
    })
    return resp, 200

# --- STUNDENPLAN / AKTUELLES_FACH ---
@app.route('/stundenplan')
@require_class_context
def stundenplan():
    class_id = g.get('active_class_id') or _get_session_class_id()
    try:
        conn = get_connection()
    except Exception:
        return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
    with closing(conn):
        try:
            schedule = _load_schedule_for_class(conn, class_id)
        except mysql.connector.Error:
            return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
        return jsonify(schedule)

@app.route('/aktuelles_fach')
@require_class_context
def aktuelles_fach():
    tz = pytz.timezone('Europe/Berlin')
    now = datetime.datetime.now(tz)
    tag = now.strftime('%A')
    class_id = g.get('active_class_id') or _get_session_class_id()
    try:
        conn = get_connection()
    except Exception:
        return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
    with closing(conn):
        try:
            plan = _load_schedule_for_day(conn, class_id, tag)
        except mysql.connector.Error:
            return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503

    current  = {
        "fach": "Frei",
        "verbleibend": "-",
        "raum": "-",
        "start": None,
        "ende": None,
        "verbleibende_sekunden": 0,
        "gesamt_sekunden": 0,
    }
    next_cls = {"start":None,"fach":"-","raum":"-"}
    def parse_time(value):
        try:
            parts = (value or '').split(':')
            hour = int(parts[0])
            minute = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            return None
        return now.replace(hour=hour, minute=minute, second=0, microsecond=0)

    for slot in plan:
        start = parse_time(slot.get("start"))
        ende  = parse_time(slot.get("end"))
        if not start or not ende:
            continue
        if start <= now <= ende:
            gesamt = int((ende - start).total_seconds())
            verbleibend = max(int((ende - now).total_seconds()), 0)
            m, s = divmod(verbleibend, 60)
            current = {
                "fach": slot.get("fach"),
                "verbleibend": f"{m:02d}:{s:02d}",
                "raum": slot.get("raum") or "-",
                "start": start.strftime("%H:%M"),
                "ende": ende.strftime("%H:%M"),
                "verbleibende_sekunden": verbleibend,
                "gesamt_sekunden": gesamt,
            }
        elif start > now and (slot.get("raum") or "-") != "-":
            if next_cls["start"] is None or start<next_cls["start"]:
                next_cls={"start":start,"fach":slot.get("fach"),"raum":slot.get("raum") or "-"}

    next_start = f"{next_cls['start'].hour:02d}:{next_cls['start'].minute:02d}" if next_cls["start"] else "-"
    response = {
        **current,
        "naechste_start": next_start,
        "naechster_raum": next_cls["raum"],
        "naechstes_fach": next_cls["fach"],
    }
    if next_cls["start"]:
        response["naechste_start_iso"] = next_cls["start"].isoformat()
    return jsonify(response)


@app.route('/tagesuebersicht')
@require_class_context
def tagesuebersicht():
    tz = pytz.timezone('Europe/Berlin')
    now = datetime.datetime.now(tz)
    heute = now.strftime('%A')
    morgen = (now + datetime.timedelta(days=1)).strftime('%A')
    class_id = g.get('active_class_id') or _get_session_class_id()
    try:
        conn = get_connection()
    except Exception:
        return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
    with closing(conn):
        try:
            heute_rows = _load_schedule_for_day(conn, class_id, heute)
            morgen_rows = _load_schedule_for_day(conn, class_id, morgen)
        except mysql.connector.Error:
            return jsonify({'status': 'error', 'message': 'database_unavailable'}), 503
        return jsonify({heute: heute_rows, morgen: morgen_rows})

# --- EINTRAG HINZUFÜGEN ---
@app.route('/add_entry', methods=['POST', 'OPTIONS'])
@require_class_admin
@require_class_context
def add_entry():
    if request.method == 'OPTIONS':
        return _cors_preflight()

    data = request.json or {}
    try:
        class_id = _normalize_entry_class_id(data.get('class_id'))
    except ValueError:
        return jsonify(status='error', message='invalid_class_id'), 400
    beschreibung = (data.get("beschreibung") or '').strip()
    datum = data.get("datum")
    startzeit = data.get("startzeit")
    endzeit = data.get("endzeit")
    typ = data.get("typ")
    fach = (data.get("fach") or '').strip()

    if datum and 'T' in datum:
        date_part, time_part = datum.split('T', 1)
        if not startzeit:
            startzeit = time_part or None
        datum = date_part

    if startzeit == '':
        startzeit = None
    if endzeit == '':
        endzeit = None

    if startzeit:
        startzeit = startzeit.strip()
        if len(startzeit) == 5:
            startzeit = f"{startzeit}:00"
        startzeit = startzeit[:8]
    if endzeit:
        endzeit = endzeit.strip()
        if len(endzeit) == 5:
            endzeit = f"{endzeit}:00"
        endzeit = endzeit[:8]

    if not typ or not datum:
        return jsonify(status="error", message="typ und datum sind erforderlich"), 400
    if typ != 'event' and not fach:
        return jsonify(status="error", message="fach ist für diesen Typ erforderlich"), 400
    if typ == 'event' and not fach:
        fach = ''

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO eintraege (class_id, beschreibung, datum, startzeit, endzeit, typ, fach)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (class_id, beschreibung, datum, startzeit, endzeit, typ, fach)
        )
        conn.commit()
        return jsonify(status="ok")
    except Exception as e:
        return jsonify(status="error", message=str(e)), 500
    finally:
        cur.close(); conn.close()
        
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# ---------- SERVER START ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)



