"""Configure the local Nextcloud demo with per-user WebDAV credentials.

Uses occ and authenticated HTTPS requests. Secrets are read from .runtime,
passed through environment or request bodies, and never printed.
"""
import argparse
import html
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import httpx

ROOT = Path(__file__).resolve().parents[1]


def setup(docker='docker', url='https://localhost:8443'):
    runtime = ROOT / '.runtime'
    storage_users = json.loads((runtime / 'users.json').read_text())
    credentials_file = runtime / 'nextcloud-users.json'
    if credentials_file.exists():
        app_users = json.loads(credentials_file.read_text())
    else:
        app_users = {name: secrets.token_urlsafe(24) for name in ('alice', 'bob')}
        credentials_file.write_text(json.dumps(app_users, indent=2), encoding='utf-8')
        os.chmod(credentials_file, 0o600)
    private = [*storage_users.values(), *app_users.values()]
    compose = [docker, 'compose', '-f', 'compose.yaml', '-f', 'compose.nextcloud.yaml']

    def run(args, env=None):
        result = subprocess.run(compose + args, cwd=ROOT, env=env, capture_output=True, timeout=120)
        output = result.stdout.decode('utf-8', errors='replace')
        if result.returncode:
            message = result.stderr.decode('utf-8', errors='replace') or output
            for secret in private:
                message = message.replace(secret, '[redacted]')
            raise RuntimeError(message[:1500])
        return output

    def occ(*args):
        return run(['exec', '-T', '-u', 'www-data', 'nextcloud', 'php', 'occ', *args])

    status = json.loads(occ('status', '--output=json'))
    if not status.get('installed'):
        raise RuntimeError('Wait until Nextcloud installation completes, then rerun.')
    occ('app:enable', 'files_external')
    occ('security:certificates:import', '/tmp/pattern-ca.pem')
    occ('config:system:set', 'allow_local_remote_servers', '--type=boolean', '--value=true')
    occ('config:system:set', 'enable_previews', '--type=boolean', '--value=false')
    current_users = json.loads(occ('user:list', '--output=json'))
    for name, password in app_users.items():
        if name not in current_users:
            env = {**os.environ, 'OC_PASS': password}
            run(['exec', '-T', '-u', 'www-data', '--env', 'OC_PASS', 'nextcloud',
                 'php', 'occ', 'user:add', '--password-from-env', name], env=env)

    mounts = json.loads(occ('files_external:list', '--output=json'))
    existing = [m for m in mounts if m.get('mount_point', m.get('mountPoint')) == '/Protected']
    if existing:
        mount_id = str(existing[0].get('mount_id', existing[0].get('id')))
    else:
        created = occ('files_external:create', '/Protected', 'dav', 'password::userprovided',
                      '-c', 'host=order-api:8443', '-c', 'root=/dav', '-c', 'secure=true',
                      '--applicable-user', 'alice', '--applicable-user', 'bob', '--output=json')
        parsed = json.loads(created)
        mount_id = str(parsed.get('mount_id', parsed.get('id'))) if isinstance(parsed, dict) else str(parsed)
    occ('files_external:option', mount_id, 'enable_sharing', 'false')
    occ('files_external:option', mount_id, 'previews', 'false')
    context = ssl.create_default_context(cafile=str(runtime / 'ca.pem'))
    for name, password in app_users.items():
        with httpx.Client(base_url=url, verify=context, trust_env=False,
                          timeout=60, follow_redirects=True,
                          headers={'Origin': url, 'Referer': url + '/login'}) as client:
            login = client.get('/login')
            login.raise_for_status()
            def token(page):
                match = re.search(r'data-requesttoken="([^"]+)"', page.text)
                if not match:
                    raise RuntimeError('Nextcloud request token not found')
                return html.unescape(match.group(1))
            response = client.post('/login', data={
                'user': name, 'password': password, 'requesttoken': token(login)})
            response.raise_for_status()
            if '/login' in response.url.path:
                raise RuntimeError('Nextcloud session login failed')
            headers = {'requesttoken': token(response), 'OCS-APIRequest': 'true'}
            confirmed = client.post('/login/confirm', json={'password': password}, headers=headers)
            confirmed.raise_for_status()
            endpoint = '/apps/files_external/userglobalstorages/' + mount_id
            body = {'backendOptions': {'user': name, 'password': storage_users[name]}}
            result = client.put(endpoint, json=body, headers=headers, auth=(name, password))
            if result.status_code == 412:
                confirmed = client.post('/login/confirm', json={'password': password}, headers=headers)
                confirmed.raise_for_status()
                result = client.put(endpoint, json=body, headers=headers, auth=(name, password))
            if result.is_error:
                try:
                    message = result.json().get('message', '')
                except (ValueError, AttributeError):
                    message = 'non-JSON response'
                raise RuntimeError('Storage settings HTTP ' + str(result.status_code) + ': ' + str(message)[:200])
            info = result.json()
            if info.get('status') not in (0, '0'):
                raise RuntimeError('External storage check failed: status=' + str(info.get('status')))
            print(name + ': personal WebDAV connection ready')
    (runtime / 'nextcloud-mount.json').write_text(json.dumps({'id': mount_id}), encoding='utf-8')
    print('Protected configured; credentials remain in ignored .runtime files.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--docker', default='docker')
    parser.add_argument('--url', default='https://localhost:8443')
    args = parser.parse_args()
    setup(args.docker, args.url)
