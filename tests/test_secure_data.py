import time
from typing import Dict


def test_secure_data_requires_login(app_client):
    client, _, _ = app_client
    resp = client.get('/api/secure-data')
    assert resp.status_code == 403


def test_secure_data_after_login(app_client):
    client, _, _ = app_client
    resp = client.post('/api/auth/login', json={'email': 'admin@example.com', 'password': 'adminpw'})
    assert resp.status_code == 200
    resp = client.get('/api/secure-data')
    assert resp.status_code == 200


def _login_admin(client):
    resp = client.post('/api/auth/login', json={'email': 'admin@example.com', 'password': 'adminpw'})
    assert resp.status_code == 200


def test_admin_users_crud_and_pagination(app_client):
    client, storage, _ = app_client
    _login_admin(client)

    resp = client.post(
        '/api/admin/users',
        json={
            'email': 'teacher@example.com',
            'password': 'Secret123!',
            'role': 'teacher',
            'class_id': 1,
            'is_active': True,
        },
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert data['status'] == 'ok'
    new_user_id = data['id']
    assert new_user_id in storage['users']

    resp = client.get('/api/admin/users?page=1&page_size=5')
    paginated = resp.get_json()
    assert resp.status_code == 200
    assert paginated['pagination']['total'] == len(storage['users'])

    resp = client.put(
        f'/api/admin/users/{new_user_id}',
        json={'role': 'admin', 'is_active': False},
    )
    assert resp.status_code == 200
    assert storage['users'][new_user_id]['role'] == 'admin'
    assert storage['users'][new_user_id]['is_active'] == 0

    resp = client.delete(f'/api/admin/users/{new_user_id}')
    assert resp.status_code == 200
    assert new_user_id not in storage['users']

    assert any(entry['action'] == 'delete' and entry['entity_type'] == 'user' for entry in storage['audit_logs'])


def test_admin_classes_and_schedules_crud(app_client):
    client, storage, _ = app_client
    _login_admin(client)

    resp = client.post(
        '/api/admin/classes',
        json={
            'slug': 'new-class',
            'title': 'Neue Klasse',
            'description': 'Test',
            'is_active': True,
        },
    )
    class_data = resp.get_json()
    assert resp.status_code == 200
    new_class_id = class_data['id']
    assert new_class_id in storage['classes']

    resp = client.put(
        f'/api/admin/classes/{new_class_id}',
        json={'title': 'Aktualisierte Klasse', 'is_active': False},
    )
    assert resp.status_code == 200
    assert storage['classes'][new_class_id]['title'] == 'Aktualisierte Klasse'
    assert storage['classes'][new_class_id]['is_active'] == 0

    resp = client.post(
        '/api/admin/schedules',
        json={'class_id': new_class_id, 'source': 'manual', 'import_hash': 'abc123'},
    )
    schedule_data = resp.get_json()
    assert resp.status_code == 200
    schedule_id = schedule_data['id']
    assert schedule_id in storage['class_schedules']

    resp = client.put(
        f'/api/admin/schedules/{schedule_id}',
        json={'source': 'imported', 'import_hash': 'xyz987'},
    )
    assert resp.status_code == 200
    assert storage['class_schedules'][schedule_id]['source'] == 'imported'

    resp = client.delete(f'/api/admin/schedules/{schedule_id}')
    assert resp.status_code == 200
    assert schedule_id not in storage['class_schedules']

    resp = client.delete(f'/api/admin/classes/{new_class_id}')
    assert resp.status_code == 200
    assert new_class_id not in storage['classes']

    actions = {(entry['entity_type'], entry['action']) for entry in storage['audit_logs']}
    assert ('class', 'delete') in actions
    assert ('schedule', 'delete') in actions
    assert resp.get_json().get('status') == 'ok'
    admin_id = storage['users_by_email']['admin@example.com']
    admin = storage['users'][admin_id]
    assert admin['last_login_updates'], 'last_login should be updated'


def test_contact_requires_valid_data(app_client):
    client, _, _ = app_client
    resp = client.post('/api/contact', data={})
    assert resp.status_code == 400


def test_contact_success(app_client, monkeypatch):
    client, _, app_module = app_client
    monkeypatch.setattr(app_module, 'CONTACT_SMTP_HOST', 'smtp.test.local')
    monkeypatch.setattr(app_module, 'CONTACT_RECIPIENT', 'dest@example.com')
    monkeypatch.setattr(app_module, 'CONTACT_FROM_ADDRESS', 'noreply@example.com')

    sent: Dict[str, object] = {}

    def fake_send(name, email, subject, body, attachment):
        sent['name'] = name
        sent['email'] = email
        sent['subject'] = subject
        sent['body'] = body
        sent['attachment'] = attachment

    monkeypatch.setattr(app_module, '_send_contact_email', fake_send)

    resp = client.post(
        '/api/contact',
        data={
            'name': 'Tester',
            'email': 'tester@example.com',
            'subject': 'Feedback',
            'message': 'Dies ist eine ausführliche Nachricht.' * 2,
            'consent': 'true',
            'hm-contact-start': str(int(time.time() * 1000)),
        },
    )
    assert resp.status_code == 200
    assert sent.get('subject') == 'Feedback'
    assert 'Tester' in sent.get('body', '')


def test_resend_verification_sends_mail(app_client, monkeypatch):
    client, storage, app_module = app_client

    sent: Dict[str, object] = {}

    def fake_send_verification(email, token, expires_at):
        sent['email'] = email
        sent['token'] = token
        sent['expires_at'] = expires_at

    monkeypatch.setattr(app_module, '_send_verification_email', fake_send_verification)

    admin_id = storage['users_by_email']['admin@example.com']
    storage['users'][admin_id]['email_verified_at'] = None

    resp = client.post('/api/auth/resend', json={'email': 'admin@example.com'})
    assert resp.status_code == 200
    assert sent.get('email') == 'admin@example.com'
    assert storage['verifications'], 'verification entry should be stored'
