import hashlib
import json
import os
import threading
import time
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from fastapi import HTTPException, Request
from prometheus_client import Counter
from .common import app_base, db, require_token, call, normalize, b64, unb64, MAX_FILE


def create_app(cfg):
    app = app_base('security-crypto')
    lock = threading.RLock()  # One worker and one replica per service in this prototype.
    decisions = Counter('pattern_decisions_total', 'Access decisions', ['result'], registry=app.state.registry)
    with db(cfg, 'keys.db') as con:
        con.executescript('''
          CREATE TABLE IF NOT EXISTS nodes (owner TEXT, path TEXT, kind TEXT, oid TEXT,
            size INTEGER, modified REAL, PRIMARY KEY(owner,path));
          CREATE TABLE IF NOT EXISTS versions (oid TEXT PRIMARY KEY, owner TEXT,
            key BLOB, nonce BLOB, ciphertext BLOB);
          CREATE TABLE IF NOT EXISTS requests (owner TEXT, rid TEXT, fingerprint TEXT,
            oid TEXT, committed INTEGER, PRIMARY KEY(owner,rid));
        ''')

    def audit(subject, action, result, oid=''):
        return call(cfg, 'audit_url', 'audit_token', '/event',
                    {'subject': subject, 'action': action, 'result': result, 'object_id': oid})

    def row(con, owner, path):
        r = con.execute('SELECT * FROM nodes WHERE owner=? AND path=?', (owner, path)).fetchone()
        if not r:
            raise HTTPException(404, 'Resource unavailable')
        return dict(r)

    def public(r):
        return {k: r[k] for k in ('path', 'kind', 'oid', 'size', 'modified')}

    @app.post('/operate')
    def operate(body: dict, request: Request):
        # Both service and user are checked, independently of order-api.
        try:
            require_token(request, cfg['order_token'])
        except HTTPException:
            decisions.labels('denied').inc()
            try:
                audit('unverified', 'service-auth', 'denied')
            except HTTPException:
                pass
            raise
        op = body.get('op', '')
        path = normalize(body.get('path', '/'))
        actions = {'put': 'write', 'get': 'read', 'stat': 'stat', 'list': 'list',
                   'mkdir': 'mkdir', 'delete': 'delete', 'move': 'move'}
        if op not in actions:
            raise HTTPException(400, 'Invalid operation')
        try:
            decision = call(cfg, 'identity_url', 'policy_token', '/authorize',
                            {'action': actions[op], 'path': path}, request.headers.get('authorization', ''))
        except HTTPException:
            decisions.labels('denied').inc()
            try:
                audit('unverified', op, 'denied')
            except HTTPException:
                pass  # Still deny when audit fails; never fall back to plaintext.
            raise
        owner = decision['subject']
        decisions.labels('allowed').inc()
        with lock, db(cfg, 'keys.db') as con:
            con.execute('INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?)', (owner, '/', 'dir', '', 0, time.time()))
            con.commit()
            if op == 'stat':
                return public(row(con, owner, path))
            if op == 'list':
                if row(con, owner, path)['kind'] != 'dir':
                    raise HTTPException(409, 'Not a collection')
                prefix = path.rstrip('/') + '/'
                entries = [public(dict(r)) for r in con.execute('SELECT * FROM nodes WHERE owner=?', (owner,))
                           if r['path'].startswith(prefix) and r['path'] != path
                           and '/' not in r['path'][len(prefix):]]
                return {'items': entries}
            if op == 'get':
                node = row(con, owner, path)
                if node['kind'] != 'file':
                    raise HTTPException(409, 'Not a file')
                version = con.execute('SELECT * FROM versions WHERE oid=? AND owner=?', (node['oid'], owner)).fetchone()
                blob = call(cfg, 'cloud_url', 'cloud_token', '/object', {'op': 'get', 'id': node['oid']})
                try:
                    plain = AESGCM(version['key']).decrypt(version['nonce'], unb64(blob['data']),
                                                          (owner + ':' + node['oid']).encode())
                except (InvalidTag, ValueError):
                    audit(owner, op, 'failed', node['oid'])
                    raise HTTPException(502, 'Encrypted object verification failed')
                # This acknowledges authorization before release, NOT receipt by the browser.
                audit(owner, op, 'authorized', node['oid'])
                return {'data': b64(plain), **public(node)}
            if path == '/':
                raise HTTPException(403, 'Root cannot be changed')
            parent = path.rsplit('/', 1)[0] or '/'
            if row(con, owner, parent)['kind'] != 'dir':
                raise HTTPException(409, 'Invalid parent')
            if op == 'put':
                data = unb64(body.get('data', ''))
                if len(data) > MAX_FILE:
                    raise HTTPException(413, 'File too large')
                existing = con.execute('SELECT kind FROM nodes WHERE owner=? AND path=?', (owner, path)).fetchone()
                if existing and existing['kind'] != 'file':
                    raise HTTPException(409, 'Collection exists')
                try:
                    rid = str(uuid.UUID(body['request_id']))
                except (KeyError, ValueError, TypeError):
                    raise HTTPException(400, 'UUID request_id required')
                fingerprint = hashlib.sha256(path.encode() + b'\0' + data).hexdigest()
                old = con.execute('SELECT * FROM requests WHERE owner=? AND rid=?', (owner, rid)).fetchone()
                if old and old['fingerprint'] != fingerprint:
                    raise HTTPException(409, 'Idempotency conflict')
                if old and old['committed']:
                    return {'id': old['oid'], 'replayed': True}
                if old:
                    oid = old['oid']
                    ciphertext = con.execute('SELECT ciphertext FROM versions WHERE oid=?', (oid,)).fetchone()[0]
                else:
                    oid = str(uuid.uuid4())
                    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
                    ciphertext = AESGCM(key).encrypt(nonce, data, (owner + ':' + oid).encode())
                    # Persist the pending ciphertext before contacting the provider.
                    con.execute('INSERT INTO versions VALUES (?,?,?,?,?)', (oid, owner, key, nonce, ciphertext))
                    con.execute('INSERT INTO requests VALUES (?,?,?,?,0)', (owner, rid, fingerprint, oid))
                    con.commit()
                stored = call(cfg, 'cloud_url', 'cloud_token', '/object', {'op': 'put', 'id': oid, 'data': b64(ciphertext)})
                if stored.get('sha256') != hashlib.sha256(ciphertext).hexdigest():
                    raise HTTPException(502, 'Storage acknowledgement mismatch')
                audit(owner, op, 'authorized', oid)
                con.execute('INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?)', (owner, path, 'file', oid, len(data), time.time()))
                con.execute('UPDATE requests SET committed=1 WHERE owner=? AND rid=?', (owner, rid))
                return {'id': oid, 'replayed': False}
            if op == 'mkdir':
                if con.execute('SELECT 1 FROM nodes WHERE owner=? AND path=?', (owner, path)).fetchone():
                    raise HTTPException(409, 'Resource exists')
                audit(owner, op, 'authorized')
                con.execute('INSERT INTO nodes VALUES (?,?,?,?,?,?)', (owner, path, 'dir', '', 0, time.time()))
                return {'created': True}
            current = row(con, owner, path)
            affected = [dict(r) for r in con.execute('SELECT * FROM nodes WHERE owner=?', (owner,))
                        if r['path'] == path or r['path'].startswith(path + '/')]
            if op == 'delete':
                audit(owner, op, 'authorized', current['oid'])
                con.executemany('DELETE FROM nodes WHERE owner=? AND path=?', [(owner, r['path']) for r in affected])
                return {'deleted': True}
            dest = normalize(body.get('destination', ''))
            if dest == '/' or dest == path or dest.startswith(path + '/'):
                raise HTTPException(409, 'Invalid destination')
            if row(con, owner, dest.rsplit('/', 1)[0] or '/')['kind'] != 'dir':
                raise HTTPException(409, 'Invalid destination parent')
            if con.execute('SELECT 1 FROM nodes WHERE owner=? AND path=?', (owner, dest)).fetchone():
                raise HTTPException(409, 'Destination exists')
            audit(owner, op, 'authorized', current['oid'])
            for r in affected:
                con.execute('UPDATE nodes SET path=? WHERE owner=? AND path=?', (dest + r['path'][len(path):], owner, r['path']))
            return {'moved': True}

    return app
