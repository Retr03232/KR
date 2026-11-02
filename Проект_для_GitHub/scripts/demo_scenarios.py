"""Demonstrate C1/C2 on the local Compose stand; stdlib-only host client.

Creates synthetic documents and a copy of the ciphertext database. Never copies
the trusted key database or writes credentials to reports. No service is stopped.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'reports' / 'two-scenarios'
STATE = OUT / 'session.json'
COMPOSE = ['docker', 'compose', '-f', 'compose.yaml', '-f', 'compose.nextcloud.yaml']


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def container(service, script, payload=None):
    result = subprocess.run(
        COMPOSE + ['exec', '-T', service, 'python', '-c', script],
        cwd=ROOT, input=json.dumps(payload).encode(), capture_output=True, timeout=90)
    require(result.returncode == 0,
            f'Ошибка диагностики {service}. Проверь состояние контейнеров и их журналы.')
    return json.loads(result.stdout)


def owner_request(filename, method='GET', content=None):
    users = json.loads((ROOT / '.runtime/nextcloud-users.json').read_text())
    ca = ssl.create_default_context(cafile=str(ROOT / '.runtime/ca.pem'))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ca))
    auth = base64.b64encode(('alice:' + users['alice']).encode()).decode()
    request = urllib.request.Request(
        'https://localhost:8443/remote.php/dav/files/alice/Protected/' + filename,
        data=content, method=method,
        headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'text/plain'})
    try:
        with opener.open(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, report):
    OUT.mkdir(parents=True, exist_ok=True)
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), **report}
    target = OUT / name
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return target


def state():
    require(STATE.exists(), 'Сначала выполни команду prepare.')
    return json.loads(STATE.read_text(encoding='utf-8'))


def owner_check(s):
    status, content = owner_request(s['file'])
    require(status == 200 and sha(content) == s['plaintext_sha256'],
            f'Контроль владельца не пройден (HTTP {status}). Проверь Nextcloud и Protected.')
    return {'owner_http': status, 'owner_sha256_matches': True}


def prepare():
    unique = uuid.uuid4().hex[:12]
    filename = 'scenario-demo-' + unique + '.txt'
    marker = 'COURSEWORK-SECRET-' + unique
    content = ('Synthetic confidential document\n' + marker + '\n').encode()
    status, _ = owner_request(filename, 'PUT', content)
    require(status in (201, 204), f'Загрузка в Protected не удалась: HTTP {status}.')
    # Trusted observer retrieves only object ID, never encryption keys.
    oid = container('security-crypto', """
import json,sqlite3,sys
p=json.load(sys.stdin)
with sqlite3.connect('file:/data/keys.db?mode=ro',uri=True) as c:
    r=c.execute('SELECT oid FROM nodes WHERE owner=? AND path=?',
                ('alice',p['path'])).fetchone()
print(json.dumps(r[0] if r else None))
""", {'path': '/' + filename})
    require(oid, 'Загруженный документ отсутствует в реестре.')
    s = {'file': filename, 'object_id': oid, 'marker': marker,
         'plaintext_sha256': sha(content), 'plaintext_bytes': len(content)}
    check = owner_check(s)
    save('session.json', s)
    (OUT / filename).write_bytes(content)
    save('prepare.json', {'file': filename, 'upload_http': status, **check})
    print('ПОДГОТОВКА: УСПЕШНО')
    print('Пользователь: alice. Папка Nextcloud: Protected.')
    print('Файл:', filename)
    print('Контрольная строка:', marker)
    print('Владелец скачал файл: HTTP 200. SHA-256 совпадает.')
    print('Оригинал для сравнения:', OUT / filename)


def scenario1():
    s = state()
    check = owner_check(s)
    run = uuid.uuid4().hex[:12]
    local = OUT / ('cloud-copy-' + run + '.sqlite')
    copied = container('cloud-storage', """
import base64,json,sqlite3
with sqlite3.connect('file:/data/cloud.db?mode=ro',uri=True) as src:
    with sqlite3.connect(':memory:') as dst:
        src.backup(dst)
        data=dst.serialize()
print(json.dumps({'database':base64.b64encode(data).decode()}))
""")
    local.write_bytes(base64.b64decode(copied['database'], validate=True))
    with sqlite3.connect(local.as_uri() + '?mode=ro', uri=True) as db:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        columns = [r[1] for r in db.execute('PRAGMA table_info(objects)')]
        row = db.execute('SELECT data FROM objects WHERE id=?', (s['object_id'],)).fetchone()
    require(row is not None, 'Документ не найден в скопированной базе.')
    blob = row[0]
    marker_present = s['marker'].encode() in blob
    require(not marker_present and sha(blob) != s['plaintext_sha256'],
            'В облачном объекте найден контрольный текст или совпадает хеш исходного файла.')
    require(len(blob) == s['plaintext_bytes'] + 16, 'Неожиданный размер зашифрованного объекта.')
    require(tables == ['objects'] and columns == ['id', 'data'],
            'Структура облачной базы отличается от ожидаемой; требуется проверка.')
    report = {'scenario': 'C1', 'file': s['file'], 'database_copy': str(local),
              'tables': tables, 'columns': columns, 'plaintext_marker_present': marker_present,
              'plaintext_bytes': s['plaintext_bytes'], 'ciphertext_bytes': len(blob),
              'plaintext_sha256': s['plaintext_sha256'], 'ciphertext_sha256': sha(blob),
              'ciphertext_first_32_bytes_hex': blob[:32].hex(), **check, 'passed': True}
    target = save('scenario1.json', report)
    print('С1: КОПИРОВАНИЕ ОБЛАЧНОГО ХРАНИЛИЩА — ПРОВЕРКА ПРОЙДЕНА')
    print('Копия БД:', local)
    print('Таблица objects содержит только id и data; ключей документов в ней нет.')
    print('Начало шифротекста (HEX):', blob[:32].hex())
    print('Контрольная строка в объекте: НЕ НАЙДЕНА.')
    print('Размер: исходный файл', s['plaintext_bytes'], 'байт; шифротекст', len(blob), 'байт.')
    print('Хеш шифротекста отличается от оригинала.')
    print('Контроль владельца: HTTP 200, содержимое совпадает.')
    print('Отчёт:', target)


def scenario2():
    s = state()
    check_before = owner_check(s)
    result = container('cloud-storage', """
import json,ssl,sys,httpx
p=json.load(sys.stdin)
cfg=json.load(open('/run/pattern/config.json'))
headers={'X-Service-Token':cfg['cloud_token']}
with httpx.Client(verify=ssl.create_default_context(cafile='/run/pattern/ca.pem'),
                  trust_env=False,timeout=30) as client:
    own=client.post('https://localhost:8443/object',headers=headers,
                    json={'op':'get','id':p['id']})
    response=client.post('https://security-crypto:8443/operate',headers=headers,
                        json={'op':'get','path':p['path']})
    result={'cloud_token_valid_http':own.status_code,
            'security_http':response.status_code,
            'plaintext_marker_returned':p['marker'].encode() in response.content,
            'document_data_field_returned':False}
    try:result['document_data_field_returned']='data' in response.json()
    except ValueError:pass
    print(json.dumps(result))
""", {'id': s['object_id'], 'path': '/' + s['file'], 'marker': s['marker']})
    require(result['cloud_token_valid_http'] == 200,
            'Облачный токен не прошёл контроль действительности в cloud-storage.')
    require(result['security_http'] == 403 and not result['plaintext_marker_returned']
            and not result['document_data_field_returned'], 'Ожидаемый отказ не подтверждён.')
    check_after = owner_check(s)
    target = save('scenario2.json', {'scenario': 'C2', 'file': s['file'], **result,
                                   'owner_before': check_before, 'owner_after': check_after,
                                   'passed': True})
    print('С2: ОБЛАЧНЫЕ СЛУЖЕБНЫЕ РЕКВИЗИТЫ — ПРОВЕРКА ПРОЙДЕНА')
    print('Запрос выполнен из cloud-storage, с его настоящим токеном.')
    print('Контроль токена в cloud-storage: HTTP 200 (токен действителен).')
    print('Попытка чтения документа через security-crypto: HTTP 403 — ОТКАЗ.')
    print('Пароль пользователя и доверенный токен order-api не передавались.')
    print('Содержимое документа нарушителю не выдано.')
    print('Владелец до и после попытки: HTTP 200, SHA-256 совпадает.')
    print('Отчёт:', target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=['prepare', 'scenario1', 'scenario2'])
    args = parser.parse_args()
    try:
        globals()[args.step]()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ПРОВЕРКА НЕ ЗАВЕРШЕНА:', str(exc), file=sys.stderr)
        print('Старый JSON-отчёт не является результатом этого запуска.', file=sys.stderr)
        sys.exit(1)
