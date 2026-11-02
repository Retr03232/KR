import hashlib
import uuid
from fastapi import HTTPException, Request
from .common import app_base, db, require_token, b64, unb64, MAX_FILE


def create_app(cfg):
    app = app_base('cloud-storage')
    with db(cfg, 'cloud.db') as con:
        con.execute('CREATE TABLE IF NOT EXISTS objects (id TEXT PRIMARY KEY, data BLOB NOT NULL)')

    @app.post('/object')
    def object_op(body: dict, request: Request):
        require_token(request, cfg['cloud_token'])
        try:
            oid = str(uuid.UUID(body['id']))
        except (KeyError, ValueError, TypeError):
            raise HTTPException(400, 'Invalid object')
        with db(cfg, 'cloud.db') as con:
            row = con.execute('SELECT data FROM objects WHERE id=?', (oid,)).fetchone()
            if body.get('op') == 'put':
                data = unb64(body.get('data', ''))
                if not 16 <= len(data) <= MAX_FILE + 16:
                    raise HTTPException(413, 'Object too large or invalid')
                if row and row['data'] != data:
                    raise HTTPException(409, 'Immutable object conflict')
                con.execute('INSERT OR IGNORE INTO objects VALUES (?,?)', (oid, data))
                return {'id': oid, 'sha256': hashlib.sha256(data).hexdigest()}
            if body.get('op') == 'get' and row:
                return {'id': oid, 'data': b64(row['data'])}
            raise HTTPException(404, 'Object unavailable')

    return app
