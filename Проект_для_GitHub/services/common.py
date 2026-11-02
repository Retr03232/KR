import base64
from contextlib import contextmanager
import hmac
import json
import os
from pathlib import Path
import sqlite3
import ssl
import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

MAX_FILE = 10 * 1024 * 1024  # Prototype memory budget; not a measured production limit.
MAX_BODY = 15 * 1024 * 1024  # Includes Base64 and JSON overhead.


def settings():
    return json.loads(Path(os.environ['PATTERN_CONFIG']).read_text(encoding='utf-8'))


@contextmanager
def db(cfg, name):
    path = Path(cfg['data_dir'])
    path.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path / name, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=FULL')
    try:
        with con:
            yield con
    finally:
        con.close()


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(data):
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError):
        raise HTTPException(400, 'Invalid encoding')


def require_token(request, expected):
    actual = request.headers.get('x-service-token', '')
    if not actual or not hmac.compare_digest(actual, expected):
        raise HTTPException(403, 'Service access denied')


def call(cfg, target, token_name, path, payload, authorization=''):
    try:
        ctx = ssl.create_default_context(cafile=cfg['ca_file'])
        with httpx.Client(verify=ctx, timeout=15, trust_env=False) as client:
            r = client.post(cfg[target] + path, json=payload, headers={
                'X-Service-Token': cfg[token_name], 'Authorization': authorization})
        if r.status_code >= 400:
            # No internal response body, credentials or provider error is reflected.
            raise HTTPException(r.status_code if r.status_code < 500 else 503,
                                'Request denied' if r.status_code < 500 else 'Dependency unavailable')
        return r.json()
    except (httpx.HTTPError, ValueError, OSError):
        raise HTTPException(503, 'Dependency unavailable')


class BodyLimit:
    """Limit bodies before JSON/WSGI buffering; reject chunked overflows too."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            msg = await receive()
            if msg['type'] == 'http.disconnect':
                return
            total += len(msg.get('body', b''))
            if total > MAX_BODY:
                return await Response(status_code=413)(scope, receive, send)
            chunks.append(msg)
            if not msg.get('more_body'):
                break
        index = 0
        async def replay():
            nonlocal index
            if index < len(chunks):
                msg = chunks[index]
                index += 1
                return msg
            return await receive()
        await self.app(scope, replay, send)


def app_base(role):
    app = FastAPI(title=role, docs_url=None, redoc_url=None, openapi_url=None)
    registry = CollectorRegistry()
    requests = Counter('pattern_requests_total', 'Completed HTTP requests',
                       ['service', 'method', 'status'], registry=registry)
    latency = Histogram('pattern_request_seconds', 'HTTP processing latency',
                        ['service'], registry=registry)
    app.state.registry = registry

    @app.middleware('http')
    async def measure(request, next_handler):
        start = time.monotonic()
        response = await next_handler(request)
        if request.url.path not in ('/health', '/metrics'):
            requests.labels(role, request.method, str(response.status_code)).inc()
            latency.labels(role).observe(time.monotonic() - start)
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/health')
    def health():
        return {'service': role, 'status': 'ready'}

    @app.get('/metrics')
    def metrics():
        return Response(generate_latest(registry), media_type='text/plain; version=0.0.4')

    app.add_middleware(BodyLimit)
    return app


def normalize(path):
    if not isinstance(path, str) or len(path) > 1024 or '\\' in path:
        raise HTTPException(400, 'Invalid path')
    parts = path.strip('/').split('/') if path.strip('/') else []
    if any(p in ('', '.', '..') or any(ord(c) < 32 for c in p) for p in parts):
        raise HTTPException(400, 'Invalid path')
    return '/' + '/'.join(parts)
