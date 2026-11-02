import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import httpx
import pytest
from scripts.bootstrap import bootstrap, ROLES

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='session')
def stack(tmp_path_factory):
    root = tmp_path_factory.mktemp('services') / 'runtime'
    sockets = []
    for _ in ROLES:
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        sockets.append(sock)
    ports = {role: sock.getsockname()[1] for role, sock in zip(ROLES, sockets)}
    for sock in sockets:
        sock.close()
    users = bootstrap(root, local=True, ports=ports)
    context = ssl.create_default_context(cafile=str(root / 'ca.pem'))
    client = httpx.Client(verify=context, trust_env=False, timeout=30)
    processes, logs = {}, {}

    def start(role):
        cfg = root / role / 'config.json'
        env = {**os.environ, 'PATTERN_CONFIG': str(cfg), 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')}
        logs[role] = open(root / (role + '.log'), 'ab')
        processes[role] = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'services.main:app',
            '--host', '127.0.0.1', '--port', str(ports[role]), '--no-access-log',
            '--ssl-certfile', str(root / role / 'server.pem'),
            '--ssl-keyfile', str(root / role / 'server-key.pem')],
            cwd=ROOT, env=env, stdout=logs[role], stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if processes[role].poll() is not None:
                raise RuntimeError((root / (role + '.log')).read_text(errors='replace'))
            try:
                if client.get(f'https://localhost:{ports[role]}/health').status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.1)
        raise RuntimeError('Startup timeout: ' + role)

    def stop(role):
        p = processes.get(role)
        if p and p.poll() is None:
            p.terminate()
            p.wait(timeout=10)
        if role in logs:
            logs[role].close()

    try:
        for role in ROLES:
            start(role)
        # Shared reference document is fixture data, not a dependency on test order.
        dav = f'https://localhost:{ports["order-api"]}/dav'
        auth = ('alice', users['alice'])
        assert client.request('MKCOL', dav + '/docs', auth=auth).status_code == 201
        assert client.put(dav + '/docs/report.txt', auth=auth,
                          content='Конфиденциальная заявка поставщика — контрольное содержимое'.encode()).status_code == 201
        yield {'root': root, 'users': users, 'client': client,
               'url': {role: f'https://localhost:{ports[role]}' for role in ROLES},
               'start': start, 'stop': stop,
               'configs': {r: json.loads((root / r / 'config.json').read_text()) for r in ROLES}}
    finally:
        for role in ROLES:
            stop(role)
        client.close()
