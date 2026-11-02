import base64
import json
import sqlite3
import uuid
import pytest

PAYLOAD = 'Конфиденциальная заявка поставщика — контрольное содержимое'.encode()


def request(s, method, path, user='alice', **kw):
    return s['client'].request(method, s['url']['order-api'] + '/dav' + path,
        auth=(user, s['users'][user]) if user else None, **kw)


def operation(s, body, user='alice', token=None):
    return s['client'].post(s['url']['security-crypto'] + '/operate', json=body,
        headers={'X-Service-Token': token or s['configs']['security-crypto']['order_token']},
        auth=(user, s['users'][user]) if user else None)


def test_webdav_file_round_trip_and_listing(stack):
    s = stack
    response = request(s, 'MKCOL', '/roundtrip')
    assert response.status_code == 201, response.text
    assert request(s, 'PUT', '/roundtrip/report.txt', content=PAYLOAD).status_code == 201
    response = request(s, 'GET', '/roundtrip/report.txt')
    assert response.status_code == 200 and response.content == PAYLOAD
    assert request(s, 'HEAD', '/roundtrip/report.txt').headers['content-length'] == str(len(PAYLOAD))
    listing = request(s, 'PROPFIND', '/roundtrip/', headers={'Depth': '1'})
    assert listing.status_code == 207 and 'report.txt' in listing.text
    partial = request(s, 'GET', '/roundtrip/report.txt', headers={'Range': 'bytes=0-3'})
    assert partial.status_code == 206 and partial.content == PAYLOAD[:4]


def test_no_anonymous_access(stack):
    assert request(stack, 'GET', '/docs/report.txt', user=None).status_code == 401


def test_wrong_password(stack):
    s = stack
    r = s['client'].get(s['url']['order-api'] + '/dav/', auth=('alice', 'incorrect'))
    assert r.status_code == 401


def test_private_namespace_isolation(stack):
    assert request(stack, 'GET', '/docs/report.txt', user='bob').status_code == 404


def test_cloud_credentials_cannot_decrypt(stack):
    s = stack
    r = operation(s, {'op': 'get', 'path': '/docs/report.txt'}, user=None,
                  token=s['configs']['cloud-storage']['cloud_token'])
    assert r.status_code == 403 and PAYLOAD not in r.content


def test_order_service_token_without_user_is_insufficient(stack):
    r = operation(stack, {'op': 'get', 'path': '/docs/report.txt'}, user=None)
    assert r.status_code == 401 and PAYLOAD not in r.content


def test_copied_cloud_database_contains_ciphertext_only(stack):
    s = stack
    with sqlite3.connect(s['root'] / 'cloud-storage/data/cloud.db') as con:
        blobs = con.execute('SELECT data FROM objects').fetchall()
    assert blobs and all(PAYLOAD not in blob for (blob,) in blobs)
    cloud_cfg = s['configs']['cloud-storage']
    assert set(cloud_cfg) == {'role', 'ca_file', 'data_dir', 'cloud_token'}


def test_idempotency_and_conflict(stack):
    rid = str(uuid.uuid4())
    body = {'op': 'put', 'path': '/idempotent.txt', 'data': base64.b64encode(PAYLOAD).decode(), 'request_id': rid}
    first = operation(stack, body)
    second = operation(stack, body)
    assert first.status_code == second.status_code == 200
    assert first.json()['id'] == second.json()['id'] and second.json()['replayed']
    assert operation(stack, {**body, 'data': 'YWJj'}).status_code == 409


def test_webdav_rename_copy_delete(stack):
    s = stack
    assert request(s, 'PUT', '/move.txt', content=PAYLOAD).status_code == 201
    target = s['url']['order-api'] + '/dav/renamed.txt'
    response = request(s, 'MOVE', '/move.txt', headers={'Destination': target})
    assert response.status_code == 201, response.text
    assert request(s, 'GET', '/move.txt').status_code == 404
    assert request(s, 'GET', '/renamed.txt').content == PAYLOAD
    copy = s['url']['order-api'] + '/dav/copy.txt'
    assert request(s, 'COPY', '/renamed.txt', headers={'Destination': copy}).status_code == 201
    assert request(s, 'GET', '/copy.txt').content == PAYLOAD
    assert request(s, 'DELETE', '/copy.txt').status_code == 204
    assert request(s, 'GET', '/copy.txt').status_code == 404


def test_directory_rename_and_recursive_delete(stack):
    s = stack
    assert request(s, 'MKCOL', '/tree').status_code == 201
    assert request(s, 'PUT', '/tree/a.txt', content=PAYLOAD).status_code == 201
    target = s['url']['order-api'] + '/dav/renamed-tree'
    assert request(s, 'MOVE', '/tree', headers={'Destination': target}).status_code == 201
    assert request(s, 'GET', '/renamed-tree/a.txt').content == PAYLOAD
    assert request(s, 'DELETE', '/renamed-tree').status_code == 204
    assert request(s, 'GET', '/renamed-tree/a.txt').status_code == 404


def test_invalid_path(stack):
    assert operation(stack, {'op': 'get', 'path': '/../alice/secret'}).status_code == 400


def test_integrity_failure_never_returns_plaintext(stack):
    s = stack
    request(s, 'PUT', '/tamper.txt', content=PAYLOAD)
    oid = operation(s, {'op': 'stat', 'path': '/tamper.txt'}).json()['oid']
    with sqlite3.connect(s['root'] / 'cloud-storage/data/cloud.db') as con:
        blob = con.execute('SELECT data FROM objects WHERE id=?', (oid,)).fetchone()[0]
        con.execute('UPDATE objects SET data=? WHERE id=?', (bytes([blob[0] ^ 1]) + blob[1:], oid))
    r = request(s, 'GET', '/tamper.txt')
    assert r.status_code >= 500 and PAYLOAD not in r.content


@pytest.mark.parametrize('role', ['identity-policy', 'audit', 'cloud-storage'])
def test_dependency_failure_denies_release(stack, role):
    s = stack
    s['stop'](role)
    try:
        r = request(s, 'GET', '/docs/report.txt')
        assert r.status_code == 503 and PAYLOAD not in r.content
    finally:
        s['start'](role)
    assert request(s, 'GET', '/docs/report.txt').content == PAYLOAD


def test_pending_write_retries_same_ciphertext(stack):
    s = stack
    body = {'op': 'put', 'path': '/retry.txt', 'data': base64.b64encode(PAYLOAD).decode(), 'request_id': str(uuid.uuid4())}
    s['stop']('audit')
    try:
        assert operation(s, body).status_code == 503
        assert operation(s, {'op': 'stat', 'path': '/retry.txt'}).status_code == 404
        with sqlite3.connect(s['root'] / 'security-crypto/data/keys.db') as con:
            oid = con.execute('SELECT oid FROM requests WHERE rid=?', (body['request_id'],)).fetchone()[0]
    finally:
        s['start']('audit')
    assert operation(s, body).json()['id'] == oid
    assert request(s, 'GET', '/retry.txt').content == PAYLOAD


def test_restart_preserves_keys_and_files(stack):
    stack['stop']('security-crypto')
    stack['start']('security-crypto')
    assert request(stack, 'GET', '/docs/report.txt').content == PAYLOAD


def test_metrics_and_audit_no_content_or_passwords(stack):
    s = stack
    assert 'pattern_decisions_total' in s['client'].get(s['url']['security-crypto'] + '/metrics').text
    with sqlite3.connect(s['root'] / 'audit/data/audit.db') as con:
        rows = con.execute('SELECT * FROM events').fetchall()
    serialized = json.dumps(rows)
    assert rows and 'authorized' in serialized and 'denied' in serialized
    assert PAYLOAD.decode() not in serialized
    assert all(p not in serialized for p in s['users'].values())


def test_cloud_object_is_immutable(stack):
    s = stack
    oid = operation(s, {'op': 'stat', 'path': '/docs/report.txt'}).json()['oid']
    r = s['client'].post(s['url']['cloud-storage'] + '/object',
        headers={'X-Service-Token': s['configs']['cloud-storage']['cloud_token']},
        json={'op': 'put', 'id': oid, 'data': base64.b64encode(b'x' * 32).decode()})
    assert r.status_code == 409


def test_oversize_file_rejected(stack):
    r = request(stack, 'PUT', '/large.bin', content=b'x' * (10 * 1024 * 1024 + 1))
    assert r.status_code == 413
    assert request(stack, 'GET', '/large.bin').status_code == 404


def test_credentials_not_accepted_without_trusted_service(stack):
    s = stack
    r = s['client'].post(s['url']['security-crypto'] + '/operate', auth=('alice', s['users']['alice']),
                         json={'op': 'get', 'path': '/docs/report.txt'})
    assert r.status_code == 403


def test_user_revocation_and_readonly(stack):
    s = stack
    cfg_path = s['root'] / 'identity-policy/config.json'
    original = cfg_path.read_text()
    cfg = json.loads(original)
    try:
        cfg['users']['alice']['read_only'] = True
        s['stop']('identity-policy')
        cfg_path.write_text(json.dumps(cfg))
        s['start']('identity-policy')
        assert request(s, 'GET', '/docs/report.txt').content == PAYLOAD
        assert request(s, 'PUT', '/readonly.txt', content=PAYLOAD).status_code == 403
        cfg['users']['alice']['enabled'] = False
        s['stop']('identity-policy')
        cfg_path.write_text(json.dumps(cfg))
        s['start']('identity-policy')
        assert request(s, 'GET', '/docs/report.txt').status_code == 401
    finally:
        s['stop']('identity-policy')
        cfg_path.write_text(original)
        s['start']('identity-policy')
