import time
import uuid
from fastapi import HTTPException, Request
from prometheus_client import Counter
from .common import app_base, db, require_token


def create_app(cfg):
    app = app_base('audit')
    count = Counter('pattern_audit_events_total', 'Durably accepted audit events', registry=app.state.registry)
    with db(cfg, 'audit.db') as con:
        con.execute('CREATE TABLE IF NOT EXISTS events '
                    '(id TEXT PRIMARY KEY, created REAL, subject TEXT, action TEXT, result TEXT, object_id TEXT)')

    @app.post('/event')
    def event(body: dict, request: Request):
        require_token(request, cfg['audit_token'])
        if body.get('result') not in ('authorized', 'denied', 'failed'):
            raise HTTPException(400, 'Invalid event')
        vals = [str(body.get(k, '')) for k in ('subject', 'action', 'result', 'object_id')]
        if any(len(v) > 160 for v in vals):
            raise HTTPException(400, 'Invalid event')
        eid = str(uuid.uuid4())
        with db(cfg, 'audit.db') as con:
            con.execute('INSERT INTO events VALUES (?,?,?,?,?,?)', (eid, time.time(), *vals))
        count.inc()
        return {'recorded': True, 'id': eid}

    return app
