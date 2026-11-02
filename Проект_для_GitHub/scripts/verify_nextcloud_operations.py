"""Exercise a disposable folder through Nextcloud, including concurrent deletes."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import html
import json
import re
import ssl
import uuid
import httpx

ROOT = Path(__file__).resolve().parents[1]


def verify():
    users = json.loads((ROOT / '.runtime/nextcloud-users.json').read_text())
    ctx = ssl.create_default_context(cafile=str(ROOT / '.runtime/ca.pem'))
    origin = 'https://localhost:8443'
    checks = {}
    with httpx.Client(base_url=origin, verify=ctx, trust_env=False, timeout=120,
                      follow_redirects=True, headers={'Origin': origin, 'Referer': origin + '/login'}) as c:
        def token(r):
            return html.unescape(re.search(r'data-requesttoken="([^"]+)"', r.text).group(1))
        login = c.get('/login')
        logged = c.post('/login', data={'user': 'alice', 'password': users['alice'],
                                      'requesttoken': token(login)})
        assert '/login' not in logged.url.path, 'Session login failed'
        c.headers.update({'requesttoken': token(logged), 'X-Requested-With': 'XMLHttpRequest'})
        base = '/remote.php/dav/files/alice/Protected/'
        folder = base + 'operations-check-' + uuid.uuid4().hex[:10]
        def check(label, method, path, expected, **kwargs):
            r = c.request(method, path, **kwargs)
            checks[label] = r.status_code
            assert r.status_code == expected, (label, r.status_code)
            return r
        check('mkdir', 'MKCOL', folder, 201)
        file = folder + '/контроль.txt'
        check('upload', 'PUT', file, 201, content=b'initial', headers={'X-OC-Mtime': '1730000000'})
        check('overwrite', 'PUT', file, 204, content=b'updated', headers={'X-OC-Mtime': '1730000000'})
        assert check('download', 'GET', file, 200).content == b'updated'
        target = folder + '/renamed.txt'
        check('rename', 'MOVE', file, 201, headers={'Destination': origin + target})
        check('copy', 'COPY', target, 201, headers={'Destination': origin + folder + '/copy.txt'})
        check('delete_one', 'DELETE', folder + '/copy.txt', 204)
        check('deleted_absent', 'GET', folder + '/copy.txt', 404)
        paths = [folder + '/bulk-' + str(n) + '.txt' for n in range(12)]
        for i, path in enumerate(paths):
            check('prepare_' + str(i), 'PUT', path, 201, content=b'disposable test')
        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda path: c.delete(path).status_code, paths))
        checks['parallel_deletes'] = statuses
        print(json.dumps({'folder': folder, 'checks': checks}, ensure_ascii=False), flush=True)
        assert set(statuses) == {204}, statuses
        assert check('control_after_deletes', 'GET', target, 200).content == b'updated'
        check('listing_after_deletes', 'PROPFIND', folder, 207, headers={'Depth': '1'})
        check('delete_folder', 'DELETE', folder, 204)
        check('folder_absent', 'GET', folder, 404)
        check('protected_still_available', 'PROPFIND', base, 207, headers={'Depth': '1'})
    report = {'checks': checks, 'scope': 'Nextcloud session; disposable folder; 12 concurrent deletions'}
    (ROOT / 'reports/nextcloud-operations.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    verify()
