import hashlib
import hmac
from fastapi import HTTPException, Request
from .common import app_base, unb64, normalize


def create_app(cfg):
    app = app_base('identity-policy')

    @app.post('/authorize')
    def authorize(body: dict, request: Request):
        token = request.headers.get('x-service-token', '')
        if not any(hmac.compare_digest(token, t) for t in cfg['allowed_tokens']):
            raise HTTPException(403, 'Service access denied')
        try:
            scheme, encoded = request.headers.get('authorization', '').split(' ', 1)
            if scheme.lower() != 'basic':
                raise ValueError()
            username, password = unb64(encoded).decode('utf-8').split(':', 1)
        except (ValueError, UnicodeError, HTTPException):
            raise HTTPException(401, 'Authentication required')
        # Do the same KDF for unknown users to avoid a cheap user-enumeration oracle.
        record = cfg['users'].get(username, cfg['dummy_user'])
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(record['salt']),
                                     record['iterations']).hex()
        if not hmac.compare_digest(digest, record['hash']) or username not in cfg['users'] or not record['enabled']:
            raise HTTPException(401, 'Authentication required')
        action = body.get('action', '')
        if action not in ('stat', 'list', 'read', 'write', 'mkdir', 'delete', 'move'):
            raise HTTPException(403, 'Operation denied')
        normalize(body.get('path', '/'))
        if action in ('write', 'mkdir', 'delete', 'move') and record.get('read_only'):
            raise HTTPException(403, 'Operation denied')
        # Owner always comes from verified credentials, never from request JSON.
        return {'subject': username, 'namespace': username, 'action': action, 'allowed': True}

    return app
