"""Exercise the running Nextcloud -> five-service Compose stack.

Creates one demonstration file in Alice's Protected folder and keeps it there.
Only sanitized results are written to reports/nextcloud-smoke.json.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import uuid
import httpx

ROOT = Path(__file__).resolve().parents[1]


def verify(docker='docker'):
    runtime = ROOT / '.runtime'
    users = json.loads((runtime / 'nextcloud-users.json').read_text())
    compose = [docker, 'compose', '-f', 'compose.yaml', '-f', 'compose.nextcloud.yaml']
    checks = {}
    def run(args, data=None):
        p = subprocess.run(compose + args, cwd=ROOT, input=data, capture_output=True, timeout=90)
        if p.returncode:
            raise RuntimeError('Container diagnostic command failed')
        return p.stdout.decode('utf-8')
    def py(service, script, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        return json.loads(run(['exec', '-T', service, 'python', '-c', script], data))
    context = ssl.create_default_context(cafile=str(runtime / 'ca.pem'))
    filename = 'coursework-proof-' + uuid.uuid4().hex[:12] + '.txt'
    marker = 'CONFIDENTIAL-COURSEWORK-' + uuid.uuid4().hex
    content = ('Nextcloud integration proof\n' + marker + '\n').encode()
    path = '/remote.php/dav/files/alice/Protected/' + filename
    with httpx.Client(base_url='https://localhost:8443', verify=context,
                      trust_env=False, timeout=60) as client:
        browser_headers = {'X-OC-Mtime': '1730000000'}
        uploaded = client.put(path, content=content, auth=('alice', users['alice']),
                              headers=browser_headers)
        checks['nextcloud_upload_http'] = uploaded.status_code
        assert uploaded.status_code in (201, 204), checks
        content += b'Updated\n'
        overwritten = client.put(path, content=content, auth=('alice', users['alice']),
                                 headers=browser_headers)
        checks['nextcloud_overwrite_http'] = overwritten.status_code
        assert overwritten.status_code == 204, checks
        downloaded = client.get(path, auth=('alice', users['alice']))
        checks['nextcloud_download_http'] = downloaded.status_code
        assert downloaded.status_code == 200, checks
        checks['sha256_before'] = hashlib.sha256(content).hexdigest()
        checks['sha256_after'] = hashlib.sha256(downloaded.content).hexdigest()
        assert checks['sha256_before'] == checks['sha256_after'], 'Round trip mismatch'
        listing = client.request('PROPFIND', '/remote.php/dav/files/alice/Protected/',
                                 headers={'Depth': '1'}, auth=('alice', users['alice']))
        checks['listed_in_protected'] = listing.status_code == 207 and filename in listing.text
        assert checks['listed_in_protected']
        # Nextcloud may prefer an existing session cookie over Basic auth.
        # Each different identity must start without the previous user's session.
        client.cookies.clear()
        isolated = client.get('/remote.php/dav/files/bob/Protected/' + filename,
                              auth=('bob', users['bob']))
        checks['bob_same_name_http'] = isolated.status_code
        assert isolated.status_code == 404, checks
        client.cookies.clear()
        forbidden = client.get(path, auth=('bob', users['bob']))
        checks['bob_alice_path_http'] = forbidden.status_code
        assert forbidden.status_code in (403, 404), checks
        client.cookies.clear()
        anonymous = client.get(path)
        checks['anonymous_http'] = anonymous.status_code
        assert anonymous.status_code == 401, checks
    oid = py('security-crypto', "import sqlite3,json,sys; p=json.load(sys.stdin); c=sqlite3.connect('file:/data/keys.db?mode=ro',uri=True); r=c.execute('SELECT oid FROM nodes WHERE owner=? AND path=?',('alice',p['path'])).fetchone(); print(json.dumps(r[0] if r else None))", {'path': '/' + filename})
    assert oid, 'Trusted registry does not contain uploaded file'
    stored = py('cloud-storage', "import sqlite3,json,sys,hashlib; p=json.load(sys.stdin); c=sqlite3.connect('file:/data/cloud.db?mode=ro',uri=True); b=c.execute('SELECT data FROM objects WHERE id=?',(p['id'],)).fetchone()[0]; print(json.dumps({'bytes':len(b),'marker_present':p['marker'].encode() in b,'sha256':hashlib.sha256(b).hexdigest()}))", {'id': oid, 'marker': marker})
    checks['cloud_ciphertext_bytes'] = stored['bytes']
    checks['plaintext_bytes'] = len(content)
    checks['cloud_contains_plaintext_marker'] = stored['marker_present']
    checks['cloud_hash_differs'] = stored['sha256'] != checks['sha256_before']
    assert not stored['marker_present'] and checks['cloud_hash_differs']
    assert stored['bytes'] == len(content) + 16
    checks['cloud_credentials_only_http'] = py('cloud-storage', "import json,ssl,httpx; c=json.load(open('/run/pattern/config.json')); r=httpx.post('https://security-crypto:8443/operate',json={'op':'get','path':'/'},headers={'X-Service-Token':c['cloud_token']},verify=ssl.create_default_context(cafile='/run/pattern/ca.pem'),trust_env=False,timeout=20); print(json.dumps(r.status_code))")
    assert checks['cloud_credentials_only_http'] == 403
    checks['authorized_get_events'] = py('audit', "import sqlite3,json,sys; p=json.load(sys.stdin); c=sqlite3.connect('file:/data/audit.db?mode=ro',uri=True); print(json.dumps(c.execute(\"SELECT count(*) FROM events WHERE subject='alice' AND action='get' AND result='authorized' AND object_id=?\",(p['id'],)).fetchone()[0]))", {'id': oid})
    assert checks['authorized_get_events'] >= 1
    with httpx.Client(trust_env=False, timeout=15) as client:
        result = client.get('http://localhost:9090/api/v1/targets').json()
    checks['prometheus_targets'] = {x['labels']['job']: x['health'] for x in result['data']['activeTargets']}
    assert len(checks['prometheus_targets']) == 5 and set(checks['prometheus_targets'].values()) == {'up'}
    status = json.loads(run(['exec', '-T', '-u', 'www-data', 'nextcloud', 'php', 'occ', 'status', '--output=json']))
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'nextcloud_version': status['versionstring'], 'file': filename, 'checks': checks,
              'scope': 'Docker Compose on one Windows/WSL host; not a Kubernetes or independent-provider test'}
    (ROOT / 'reports').mkdir(exist_ok=True)
    (ROOT / 'reports/nextcloud-smoke.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--docker', default='docker')
    args = parser.parse_args()
    verify(args.docker)
