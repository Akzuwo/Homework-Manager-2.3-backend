import datetime
from typing import Dict

from auth import utils as auth_utils


def test_registration_flow_requires_verification(app_client, monkeypatch):
    client, storage, app_module = app_client

    captured: Dict[str, str] = {}

    def fake_send(email, token, expires_at):
        captured['email'] = email
        captured['token'] = token
        captured['expires_at'] = expires_at.isoformat() if hasattr(expires_at, 'isoformat') else str(expires_at)

    monkeypatch.setattr(app_module, '_send_verification_email', fake_send)

    resp = client.post(
        '/api/auth/register',
        json={'email': 'student@sluz.ch', 'password': 'Secret123!'},
    )
    assert resp.status_code == 200
    assert captured.get('email') == 'student@sluz.ch'

    new_user_id = storage['users_by_email']['student@sluz.ch']
    user = storage['users'][new_user_id]
    assert user['role'] == 'student'
    assert storage['verifications'], 'verification entry should exist'
    token = storage['verifications'][-1]['token']

    resp = client.post('/api/auth/login', json={'email': 'student@sluz.ch', 'password': 'Secret123!'})
    assert resp.status_code == 403
    assert resp.get_json()['message'] == 'email_not_verified'

    resp = client.post('/api/auth/verify', json={'token': token})
    assert resp.status_code == 200

    resp = client.post('/api/auth/login', json={'email': 'student@sluz.ch', 'password': 'Secret123!'})
    assert resp.status_code == 200
    assert resp.get_json()['role'] == 'student'


def test_login_rate_limit_blocks_repeated_failures(app_client, monkeypatch):
    client, _, app_module = app_client
    app_module.LOGIN_RATE_LIMIT.clear()
    monkeypatch.setattr(app_module, 'LOGIN_RATE_LIMIT_MAX', 1)
    monkeypatch.setattr(app_module, 'LOGIN_RATE_LIMIT_WINDOW', 600)

    resp = client.post('/api/auth/login', json={'email': 'admin@example.com', 'password': 'wrong'})
    assert resp.status_code == 401

    resp = client.post('/api/auth/login', json={'email': 'admin@example.com', 'password': 'adminpw'})
    assert resp.status_code == 429
    assert resp.get_json()['message'] == 'rate_limited'


def test_student_role_cannot_access_admin(app_client):
    client, storage, _ = app_client
    now = datetime.datetime.utcnow()

    user_id = storage['next_ids']['users']
    storage['next_ids']['users'] = user_id + 1
    storage['users'][user_id] = {
        'id': user_id,
        'email': 'student@sluz.ch',
        'password_hash': auth_utils.hash_password('Student123!'),
        'role': 'student',
        'class_id': 1,
        'is_active': 1,
        'created_at': now,
        'updated_at': now,
        'email_verified_at': now,
    }
    storage['users_by_email']['student@sluz.ch'] = user_id

    resp = client.post('/api/auth/login', json={'email': 'student@sluz.ch', 'password': 'Student123!'})
    assert resp.status_code == 200

    resp = client.get('/api/admin/users')
    assert resp.status_code == 403


def test_schedule_endpoint_filters_by_class(app_client):
    client, storage, _ = app_client
    storage['stundenplan_entries'].extend(
        [
            {
                'id': 1,
                'class_id': 1,
                'tag': 'Monday',
                'start': '08:00',
                'end': '08:45',
                'fach': 'Mathematik',
                'raum': '101',
            },
            {
                'id': 2,
                'class_id': 2,
                'tag': 'Monday',
                'start': '08:00',
                'end': '08:45',
                'fach': 'Biologie',
                'raum': '202',
            },
        ]
    )

    resp = client.post('/api/auth/login', json={'email': 'admin@example.com', 'password': 'adminpw'})
    assert resp.status_code == 200

    resp = client.get('/stundenplan')
    assert resp.status_code == 200
    schedule = resp.get_json()
    assert 'Monday' in schedule
    monday_entries = schedule['Monday']
    assert any(entry['fach'] == 'Mathematik' for entry in monday_entries)
    assert all(entry['fach'] != 'Biologie' for entry in monday_entries)


def test_verification_rate_limit_blocks_after_threshold(app_client, monkeypatch):
    client, _, app_module = app_client
    app_module.VERIFY_RATE_LIMIT.clear()
    monkeypatch.setattr(app_module, 'VERIFY_RATE_LIMIT_MAX', 1)
    monkeypatch.setattr(app_module, 'VERIFY_RATE_LIMIT_WINDOW', 600)

    resp = client.post('/api/auth/verify', json={'token': 'missing'})
    assert resp.status_code == 404

    resp = client.post('/api/auth/verify', json={'token': 'missing'})
    assert resp.status_code == 429
    assert resp.get_json()['message'] == 'rate_limited'
