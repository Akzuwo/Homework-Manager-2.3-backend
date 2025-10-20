import builtins
import datetime
import importlib
import io
import os
import sys
import time
from typing import Dict, List, Optional

import pytest

# Ensure app module can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import utils as auth_utils


class FakeCursor:
    def __init__(self, storage: Dict[str, object], dictionary: bool = False) -> None:
        self.storage = storage
        self.dictionary = dictionary
        self._rows: List[object] = []
        self.rowcount = 0
        self.lastrowid: Optional[int] = None

    def _prepare_rows(self, rows: List[Dict[str, object]], columns: List[str]) -> None:
        if self.dictionary:
            self._rows = [{col: row.get(col) for col in columns} for row in rows]
        else:
            self._rows = [tuple(row.get(col) for col in columns) for row in rows]

    def execute(self, query: str, params=None) -> None:  # pragma: no cover - shim
        normalized = " ".join(query.split()).lower()
        self._rows = []
        self.rowcount = 0
        self.lastrowid = None

        users: Dict[int, Dict[str, object]] = self.storage.setdefault('users', {})
        classes: Dict[int, Dict[str, object]] = self.storage.setdefault('classes', {})
        schedules: Dict[int, Dict[str, object]] = self.storage.setdefault('class_schedules', {})
        schedule_entries: List[Dict[str, object]] = self.storage.setdefault('stundenplan_entries', [])
        entries: List[Dict[str, object]] = self.storage.setdefault('eintraege', [])

        if normalized.startswith("select count(*) as total from users"):
            self._prepare_rows([
                {'total': len(users)}
            ], ['total'])
            return

        if normalized.startswith("select id, email, password_hash, is_active, email_verified_at, role from users where role='admin'"):
            admin = next((row for row in users.values() if row.get('role') == 'admin'), None)
            if not admin:
                self._rows = []
                return
            self._prepare_rows([
                {
                    'id': admin['id'],
                    'email': admin['email'],
                    'password_hash': admin['password_hash'],
                    'is_active': admin.get('is_active', 1),
                    'email_verified_at': admin.get('email_verified_at'),
                    'role': admin.get('role'),
                }
            ], ['id', 'email', 'password_hash', 'is_active', 'email_verified_at', 'role'])
            return

        if normalized.startswith("select id, email, password_hash, role, class_id, is_active, email_verified_at") and "where email=%s" in normalized:
            email = params[0] if params else None
            user_id = self.storage.setdefault('users_by_email', {}).get(email)
            if user_id is None:
                self._rows = []
                return
            user = users.get(user_id)
            if not user:
                self._rows = []
                return
            self._prepare_rows([
                {
                    'id': user['id'],
                    'email': user['email'],
                    'password_hash': user['password_hash'],
                    'role': user.get('role', 'student'),
                    'class_id': user.get('class_id'),
                    'is_active': user.get('is_active', 1),
                    'email_verified_at': user.get('email_verified_at'),
                }
            ], ['id', 'email', 'password_hash', 'role', 'class_id', 'is_active', 'email_verified_at'])
            return

        if normalized.startswith("select id, email, role, class_id, is_active, created_at, updated_at from users order by id desc"):
            limit, offset = params
            ordered = sorted(users.values(), key=lambda row: row['id'], reverse=True)
            subset = ordered[offset:offset + limit]
            rows = [
                {
                    'id': row['id'],
                    'email': row['email'],
                    'role': row.get('role', 'student'),
                    'class_id': row.get('class_id'),
                    'is_active': row.get('is_active', 1),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                }
                for row in subset
            ]
            self._prepare_rows(rows, ['id', 'email', 'role', 'class_id', 'is_active', 'created_at', 'updated_at'])
            return

        if normalized.startswith("select id, email, role, class_id, is_active, created_at, updated_at from users where id=%s"):
            user_id = params[0]
            user = users.get(user_id)
            if not user:
                self._rows = []
                return
            self._prepare_rows([
                {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user.get('role', 'student'),
                    'class_id': user.get('class_id'),
                    'is_active': user.get('is_active', 1),
                    'created_at': user['created_at'],
                    'updated_at': user['updated_at'],
                }
            ], ['id', 'email', 'role', 'class_id', 'is_active', 'created_at', 'updated_at'])
            return

        if normalized.startswith("insert into users"):
            if len(params) == 6:
                email, password_hash, role, class_id, is_active, email_verified_at = params
                created_at = datetime.datetime.utcnow()
                updated_at = created_at
            else:
                email, password_hash, role, class_id, is_active, created_at, updated_at = params
                email_verified_at = None
            if email in self.storage.setdefault('users_by_email', {}):
                raise RuntimeError('duplicate email')
            new_id = self.storage.setdefault('next_ids', {}).setdefault('users', 1)
            self.storage['next_ids']['users'] = new_id + 1
            user_record = {
                'id': new_id,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'class_id': class_id,
                'is_active': is_active,
                'created_at': created_at,
                'updated_at': updated_at,
                'email_verified_at': email_verified_at,
            }
            users[new_id] = user_record
            self.storage['users_by_email'][email] = new_id
            self.lastrowid = new_id
            self.rowcount = 1
            return

        if normalized.startswith("update users set last_login_at"):
            user_id = params[1]
            user = users.get(user_id)
            if user:
                user.setdefault('last_login_updates', []).append(params)
                user['updated_at'] = datetime.datetime.utcnow()
                self.rowcount = 1
            return

        if normalized.startswith("update users set email_verified_at"):
            email_verified_at, user_id = params
            user = users.get(user_id)
            if user:
                user['email_verified_at'] = email_verified_at
                user['updated_at'] = datetime.datetime.utcnow()
                self.rowcount = 1
            return

        if normalized.startswith("update users set"):
            set_part = query.split('SET', 1)[1].rsplit('WHERE', 1)[0]
            assignments = [segment.strip() for segment in set_part.split(',')]
            user_id = params[-1]
            user = users.get(user_id)
            if not user:
                self.rowcount = 0
                return
            for assignment, value in zip(assignments, params[:-1]):
                column = assignment.split('=')[0].strip().strip('`')
                if column == 'email':
                    old_email = user['email']
                    if old_email != value:
                        self.storage['users_by_email'].pop(old_email, None)
                        self.storage['users_by_email'][value] = user_id
                    user['email'] = value
                elif column == 'role':
                    user['role'] = value
                elif column == 'class_id':
                    user['class_id'] = value
                elif column == 'is_active':
                    user['is_active'] = value
                elif column == 'password_hash':
                    user['password_hash'] = value
            user['updated_at'] = datetime.datetime.utcnow()
            self.rowcount = 1
            return

        if normalized.startswith("delete from users where id=%s"):
            user_id = params[0]
            user = users.pop(user_id, None)
            if user:
                self.storage['users_by_email'].pop(user['email'], None)
                self.rowcount = 1
            return

        if normalized.startswith("select count(*) as total from classes"):
            self._prepare_rows([
                {'total': len(classes)}
            ], ['total'])
            return

        if normalized.startswith("select id, slug, title, description, is_active, created_at, updated_at from classes order by title asc"):
            limit, offset = params
            ordered = sorted(classes.values(), key=lambda row: row['title'])
            subset = ordered[offset:offset + limit]
            rows = [
                {
                    'id': row['id'],
                    'slug': row['slug'],
                    'title': row['title'],
                    'description': row.get('description'),
                    'is_active': row.get('is_active', 1),
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                }
                for row in subset
            ]
            self._prepare_rows(rows, ['id', 'slug', 'title', 'description', 'is_active', 'created_at', 'updated_at'])
            return

        if normalized.startswith("select id, slug, title, description, is_active, created_at, updated_at from classes where id=%s"):
            class_id = params[0]
            cls = classes.get(class_id)
            if not cls:
                self._rows = []
                return
            self._prepare_rows([
                {
                    'id': cls['id'],
                    'slug': cls['slug'],
                    'title': cls['title'],
                    'description': cls.get('description'),
                    'is_active': cls.get('is_active', 1),
                    'created_at': cls['created_at'],
                    'updated_at': cls['updated_at'],
                }
            ], ['id', 'slug', 'title', 'description', 'is_active', 'created_at', 'updated_at'])
            return

        if normalized.startswith("select id from classes where id=%s"):
            class_id = params[0]
            if class_id in classes:
                self._prepare_rows([{'id': class_id}], ['id'])
            else:
                self._rows = []
            return

        if normalized.startswith("insert into classes"):
            slug, title, description, is_active, created_at, updated_at = params
            new_id = self.storage.setdefault('next_ids', {}).setdefault('classes', 1)
            self.storage['next_ids']['classes'] = new_id + 1
            classes[new_id] = {
                'id': new_id,
                'slug': slug,
                'title': title,
                'description': description,
                'is_active': is_active,
                'created_at': created_at,
                'updated_at': updated_at,
            }
            self.lastrowid = new_id
            self.rowcount = 1
            return

        if normalized.startswith("update classes set"):
            set_part = query.split('SET', 1)[1].rsplit('WHERE', 1)[0]
            assignments = [segment.strip() for segment in set_part.split(',')]
            class_id = params[-1]
            cls = classes.get(class_id)
            if not cls:
                self.rowcount = 0
                return
            for assignment, value in zip(assignments, params[:-1]):
                column = assignment.split('=')[0].strip().strip('`')
                cls[column] = value
            cls['updated_at'] = datetime.datetime.utcnow()
            self.rowcount = 1
            return

        if normalized.startswith("delete from classes where id=%s"):
            class_id = params[0]
            if classes.pop(class_id, None):
                self.rowcount = 1
            return

        if normalized.startswith("select count(*) as total from class_schedules"):
            self._prepare_rows([
                {'total': len(schedules)}
            ], ['total'])
            return

        if normalized.startswith("select cs.id, cs.class_id, cs.source, cs.import_hash, cs.imported_at") and "from class_schedules" in normalized:
            limit, offset = params
            ordered = sorted(schedules.values(), key=lambda row: row['id'], reverse=True)
            subset = ordered[offset:offset + limit]
            rows = []
            for entry in subset:
                class_info = classes.get(entry['class_id'], {})
                rows.append(
                    {
                        'id': entry['id'],
                        'class_id': entry['class_id'],
                        'source': entry.get('source'),
                        'import_hash': entry.get('import_hash'),
                        'imported_at': entry.get('imported_at'),
                        'created_at': entry['created_at'],
                        'updated_at': entry.get('updated_at', entry['created_at']),
                        'class_slug': class_info.get('slug'),
                        'class_title': class_info.get('title'),
                    }
                )
            self._prepare_rows(
                rows,
                ['id', 'class_id', 'source', 'import_hash', 'imported_at', 'created_at', 'updated_at', 'class_slug', 'class_title'],
            )
            return

        if normalized.startswith("select cs.id, cs.class_id, cs.source, cs.import_hash, cs.imported_at") and "where cs.id=%s" in normalized:
            schedule_id = params[0]
            entry = schedules.get(schedule_id)
            if not entry:
                self._rows = []
                return
            class_info = classes.get(entry['class_id'], {})
            self._prepare_rows(
                [
                    {
                        'id': entry['id'],
                        'class_id': entry['class_id'],
                        'source': entry.get('source'),
                        'import_hash': entry.get('import_hash'),
                        'imported_at': entry.get('imported_at'),
                        'created_at': entry['created_at'],
                        'updated_at': entry.get('updated_at', entry['created_at']),
                        'class_slug': class_info.get('slug'),
                        'class_title': class_info.get('title'),
                    }
                ],
                ['id', 'class_id', 'source', 'import_hash', 'imported_at', 'created_at', 'updated_at', 'class_slug', 'class_title'],
            )
            return

        if normalized.startswith("insert into class_schedules"):
            class_id, source, import_hash, imported_at, created_at, updated_at = params
            new_id = self.storage.setdefault('next_ids', {}).setdefault('class_schedules', 1)
            self.storage['next_ids']['class_schedules'] = new_id + 1
            schedules[new_id] = {
                'id': new_id,
                'class_id': class_id,
                'source': source,
                'import_hash': import_hash,
                'imported_at': imported_at,
                'created_at': created_at,
                'updated_at': updated_at,
            }
            self.lastrowid = new_id
            self.rowcount = 1
            return

        if normalized.startswith("update class_schedules set"):
            set_part = query.split('SET', 1)[1].rsplit('WHERE', 1)[0]
            assignments = [segment.strip() for segment in set_part.split(',')]
            schedule_id = params[-1]
            entry = schedules.get(schedule_id)
            if not entry:
                self.rowcount = 0
                return
            for assignment, value in zip(assignments, params[:-1]):
                column = assignment.split('=')[0].strip().strip('`')
                entry[column] = value
            entry['updated_at'] = datetime.datetime.utcnow()
            self.rowcount = 1
            return

        if normalized.startswith("delete from class_schedules where id=%s"):
            schedule_id = params[0]
            if schedules.pop(schedule_id, None):
                self.rowcount = 1
            return

        if normalized.startswith("insert into admin_audit_logs"):
            actor_id, action, entity_type, entity_id, details = params
            log_id = self.storage.setdefault('next_ids', {}).setdefault('audit_logs', 1)
            self.storage['next_ids']['audit_logs'] = log_id + 1
            self.storage.setdefault('audit_logs', []).append(
                {
                    'id': log_id,
                    'actor_id': actor_id,
                    'action': action,
                    'entity_type': entity_type,
                    'entity_id': entity_id,
                    'details': details,
                }
            )
            self.lastrowid = log_id
            self.rowcount = 1
            return

        if normalized.startswith("insert into email_verifications"):
            user_id, email, token, expires_at = params
            entries = self.storage.setdefault('verifications', [])
            verification_id = len(entries) + 1
            entries.append(
                {
                    'id': verification_id,
                    'user_id': user_id,
                    'email': email,
                    'token': token,
                    'expires_at': expires_at,
                    'verified_at': None,
                }
            )
            self.lastrowid = verification_id
            self.rowcount = 1
            return

        if normalized.startswith("delete from email_verifications"):
            self.storage.setdefault('verifications', []).clear()
            self.rowcount = 0
            return

        if normalized.startswith("update email_verifications set verified_at"):
            verified_at, verification_id = params
            entries = self.storage.setdefault('verifications', [])
            for entry in entries:
                if entry['id'] == verification_id:
                    entry['verified_at'] = verified_at
                    break
            self.rowcount = 1
            return

        if normalized.startswith("select id from users where id=%s"):
            user_id = params[0]
            if user_id in users:
                self._prepare_rows([{'id': user_id}], ['id'])
            else:
                self._rows = []
            return

        if normalized.startswith("select ev.id, ev.user_id, ev.token, ev.expires_at, ev.verified_at, u.email_verified_at"):
            token_value = params[0]
            entries = self.storage.setdefault('verifications', [])
            for entry in entries:
                if entry['token'] == token_value:
                    user = users.get(entry['user_id'])
                    result = {
                        'id': entry['id'],
                        'user_id': entry['user_id'],
                        'token': entry['token'],
                        'expires_at': entry['expires_at'],
                        'verified_at': entry.get('verified_at'),
                        'email_verified_at': (user or {}).get('email_verified_at'),
                    }
                    self._prepare_rows([result], ['id', 'user_id', 'token', 'expires_at', 'verified_at', 'email_verified_at'])
                    return
            self._rows = []
            return

        if normalized.startswith("select tag, start, `end`, fach, raum from stundenplan_entries"):
            class_id = params[0]
            rows = [
                {
                    'tag': entry['tag'],
                    'start': entry['start'],
                    'end': entry['end'],
                    'fach': entry['fach'],
                    'raum': entry.get('raum'),
                }
                for entry in schedule_entries
                if entry.get('class_id') == class_id
            ]
            rows.sort(key=lambda row: (row.get('tag') or '', row.get('start') or ''))
            self._prepare_rows(rows, ['tag', 'start', 'end', 'fach', 'raum'])
            return

        if normalized.startswith("select start, `end`, fach, raum from stundenplan_entries") and "tag=%s" in normalized:
            class_id, day = params
            rows = [
                {
                    'start': entry['start'],
                    'end': entry['end'],
                    'fach': entry['fach'],
                    'raum': entry.get('raum'),
                }
                for entry in schedule_entries
                if entry.get('class_id') == class_id and entry.get('tag') == day
            ]
            rows.sort(key=lambda row: row.get('start') or '')
            self._prepare_rows(rows, ['start', 'end', 'fach', 'raum'])
            return

        if normalized.startswith("delete from stundenplan_entries where class_id=%s"):
            class_id = params[0]
            before = len(schedule_entries)
            remaining = [entry for entry in schedule_entries if entry.get('class_id') != class_id]
            self.storage['stundenplan_entries'] = remaining
            self.rowcount = before - len(remaining)
            return

        if normalized.startswith("insert into stundenplan_entries"):
            class_id, tag, start, end, fach, raum = params
            new_id = self.storage.setdefault('next_ids', {}).setdefault('stundenplan_entries', 1)
            self.storage['next_ids']['stundenplan_entries'] = new_id + 1
            schedule_entries.append(
                {
                    'id': new_id,
                    'class_id': class_id,
                    'tag': tag,
                    'start': start,
                    'end': end,
                    'fach': fach,
                    'raum': raum,
                }
            )
            self.lastrowid = new_id
            self.rowcount = 1
            return

        if normalized.startswith("select fach from eintraege where id=%s and class_id=%s"):
            entry_id, class_id = params
            for entry in entries:
                if entry['id'] == entry_id and entry['class_id'] == class_id:
                    self._prepare_rows([(entry.get('fach'),)], ['fach'])
                    return
            self._rows = []
            return

        if normalized.startswith("update eintraege set beschreibung=%s, datum=%s, startzeit=%s, endzeit=%s, typ=%s, fach=%s where id=%s and class_id=%s"):
            desc, date, start, end, typ, fach, entry_id, class_id = params
            for entry in entries:
                if entry['id'] == entry_id and entry['class_id'] == class_id:
                    entry.update(
                        {
                            'beschreibung': desc,
                            'datum': date,
                            'startzeit': start,
                            'endzeit': end,
                            'typ': typ,
                            'fach': fach,
                        }
                    )
                    self.rowcount = 1
                    break
            return

        if normalized.startswith("delete from eintraege where id=%s and class_id=%s"):
            entry_id, class_id = params
            before = len(entries)
            remaining = [entry for entry in entries if not (entry['id'] == entry_id and entry['class_id'] == class_id)]
            self.storage['eintraege'] = remaining
            self.rowcount = before - len(remaining)
            return

        if normalized.startswith("insert into eintraege (class_id, beschreibung, datum, startzeit, endzeit, typ, fach)"):
            class_id, desc, date, start, end, typ, fach = params
            next_ids = self.storage.setdefault('next_ids', {})
            new_id = next_ids.setdefault('eintraege', 1)
            next_ids['eintraege'] = new_id + 1
            entry = {
                'id': new_id,
                'class_id': class_id,
                'beschreibung': desc,
                'datum': date,
                'startzeit': start,
                'endzeit': end,
                'typ': typ,
                'fach': fach,
            }
            entries.append(entry)
            self.lastrowid = new_id
            self.rowcount = 1
            return

        self._rows = []

    def fetchone(self):  # pragma: no cover - shim
        if not self._rows:
            return None
        return self._rows.pop(0)

    def fetchall(self):  # pragma: no cover - shim
        rows = list(self._rows)
        self._rows = []
        return rows

    def close(self) -> None:  # pragma: no cover - shim
        return None


class FakeConnection:
    def __init__(self, storage: Dict[str, object]) -> None:
        self.storage = storage

    def cursor(self, dictionary: bool = False):
        return FakeCursor(self.storage, dictionary=dictionary)

    def commit(self) -> None:
        self.storage['commits'] = self.storage.get('commits', 0) + 1

    def rollback(self) -> None:
        self.storage['rollbacks'] = self.storage.get('rollbacks', 0) + 1

    def close(self) -> None:  # pragma: no cover - shim
        return None


@pytest.fixture
def app_client(monkeypatch):
    real_open = builtins.open

    def mock_open(path, *args, **kwargs):
        if path == '/etc/secrets/hwm-session-secret':
            return io.StringIO('secret')
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, 'open', mock_open)

    now = datetime.datetime.utcnow()
    storage: Dict[str, object] = {
        'users': {
            1: {
                'id': 1,
                'email': 'admin@example.com',
                'password_hash': auth_utils.hash_password('adminpw'),
                'role': 'admin',
                'class_id': 1,
                'is_active': 1,
                'created_at': now,
                'updated_at': now,
                'email_verified_at': now,
                'last_login_updates': [],
            }
        },
        'users_by_email': {'admin@example.com': 1},
        'classes': {
            1: {
                'id': 1,
                'slug': 'default',
                'title': 'Default Class',
                'description': 'Default class',
                'is_active': 1,
                'created_at': now,
                'updated_at': now,
            }
        },
        'class_schedules': {},
        'stundenplan_entries': [],
        'eintraege': [],
        'audit_logs': [],
        'verifications': [],
        'next_ids': {
            'users': 2,
            'classes': 2,
            'class_schedules': 1,
            'audit_logs': 1,
            'stundenplan_entries': 1,
            'eintraege': 1,
        },
    }

    class DummyPool:
        def get_connection(self):  # pragma: no cover - shim
            raise RuntimeError('DB access disabled in tests')

    monkeypatch.setattr('mysql.connector.pooling.MySQLConnectionPool', lambda *a, **kw: DummyPool())

    app_module = importlib.import_module('app')
    app_module.app.config['TESTING'] = True
    monkeypatch.setattr(app_module, 'CONTACT_RATE_LIMIT', {})
    monkeypatch.setattr(app_module, 'CONTACT_MIN_DURATION_MS', 0)
    monkeypatch.setattr(app_module, 'LOGIN_RATE_LIMIT', {})
    monkeypatch.setattr(app_module, 'VERIFY_RATE_LIMIT', {})
    monkeypatch.setattr(app_module, 'LOGIN_RATE_LIMIT_WINDOW', 1)
    monkeypatch.setattr(app_module, 'LOGIN_RATE_LIMIT_MAX', 100)
    monkeypatch.setattr(app_module, 'VERIFY_RATE_LIMIT_WINDOW', 1)
    monkeypatch.setattr(app_module, 'VERIFY_RATE_LIMIT_MAX', 100)

    def fake_get_connection():
        return FakeConnection(storage)

    monkeypatch.setattr(app_module, 'get_connection', fake_get_connection)

    with app_module.app.test_client() as client:
        yield client, storage, app_module
