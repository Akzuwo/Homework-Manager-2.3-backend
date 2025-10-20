from class_ids import DEFAULT_ENTRY_CLASS_ID


def _authenticate(client):
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['class_id'] = 1


def test_add_entry_uses_default_class_id(app_client):
    client, storage, _ = app_client
    _authenticate(client)

    payload = {
        'typ': 'event',
        'datum': '2024-05-01',
        'beschreibung': 'Testeintrag',
    }

    resp = client.post('/add_entry', json=payload)
    assert resp.status_code == 200

    entries = storage['eintraege']
    assert entries, 'entry should have been stored'
    assert entries[0]['class_id'] == DEFAULT_ENTRY_CLASS_ID


def test_add_entry_accepts_custom_class_id(app_client):
    client, storage, _ = app_client
    _authenticate(client)

    payload = {
        'typ': 'event',
        'datum': '2024-05-02',
        'beschreibung': 'Custom class entry',
        'class_id': 'u24F',
    }

    resp = client.post('/add_entry', json=payload)
    assert resp.status_code == 200

    entries = storage['eintraege']
    assert entries[-1]['class_id'] == 'U24f'


def test_add_entry_rejects_invalid_class_id(app_client):
    client, storage, _ = app_client
    _authenticate(client)

    before_entries = list(storage['eintraege'])

    payload = {
        'typ': 'event',
        'datum': '2024-05-03',
        'beschreibung': 'Invalid class',
        'class_id': 'XYZ',
    }

    resp = client.post('/add_entry', json=payload)
    assert resp.status_code == 400
    assert storage['eintraege'] == before_entries
