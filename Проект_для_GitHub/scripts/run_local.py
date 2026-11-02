"""Run five HTTPS processes in foreground; Ctrl+C stops only these processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from bootstrap import bootstrap, ROLES

ROOT = Path(__file__).resolve().parents[1]
runtime = ROOT / '.runtime-local'
ports = {role: 18441 + index for index, role in enumerate(ROLES)}
if not runtime.exists():
    bootstrap(runtime, local=True, ports=ports)
processes, logs = [], []
try:
    for role in ROLES:
        folder = runtime / role
        log = open(runtime / (role + '.log'), 'ab')
        logs.append(log)
        env = {**os.environ, 'PATTERN_CONFIG': str(folder / 'config.json')}
        processes.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'services.main:app',
            '--host', '127.0.0.1', '--port', str(ports[role]), '--no-access-log',
            '--ssl-certfile', str(folder / 'server.pem'), '--ssl-keyfile', str(folder / 'server-key.pem')],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0))
    print('WebDAV: https://localhost:18441/dav/; credentials: .runtime-local/users.json; CA: .runtime-local/ca.pem')
    print('Ctrl+C stops the processes. Data is preserved. This is a single-host functional stand.')
    while all(p.poll() is None for p in processes):
        time.sleep(.5)
    raise RuntimeError('A service exited; inspect .runtime-local/*.log')
except KeyboardInterrupt:
    pass
finally:
    for process in processes:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
    for log in logs:
        log.close()
