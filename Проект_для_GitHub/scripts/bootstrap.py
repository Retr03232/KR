"""Create separate per-role credentials and a local test CA, never commit output."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROLES = ['order-api', 'identity-policy', 'security-crypto', 'cloud-storage', 'audit']


def bootstrap(root, local=False, ports=None):
    root = Path(root).resolve()
    if root.exists() and any(root.iterdir()):
        raise RuntimeError('Refusing to replace existing credentials: choose an empty directory')
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    tokens = {name: secrets.token_urlsafe(32) for name in ['order', 'order_policy', 'policy', 'cloud', 'audit']}
    passwords = {name: secrets.token_urlsafe(24) for name in ['alice', 'bob']}
    def user(password):
        salt = secrets.token_bytes(16)
        rounds = 600000  # Documented configuration, tune after measurements.
        return {'salt': salt.hex(), 'iterations': rounds,
                'hash': hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds).hex(),
                'enabled': True, 'read_only': False}
    users = {name: user(password) for name, password in passwords.items()}
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Coursework test CA')])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (root / 'ca.pem').write_bytes(ca_pem)
    ports = ports or {role: 8443 for role in ROLES}
    def url(role):
        return f'https://localhost:{ports[role]}' if local else f'https://{role}:8443'
    configs = {
        'order-api': {'security_url': url('security-crypto'), 'identity_url': url('identity-policy'),
                      'order_token': tokens['order'], 'policy_token': tokens['order_policy']},
        'identity-policy': {'allowed_tokens': [tokens['policy'], tokens['order_policy']],
                            'users': users, 'dummy_user': user(secrets.token_urlsafe(24))},
        'security-crypto': {'identity_url': url('identity-policy'), 'cloud_url': url('cloud-storage'),
                            'audit_url': url('audit'), 'order_token': tokens['order'],
                            'policy_token': tokens['policy'], 'cloud_token': tokens['cloud'], 'audit_token': tokens['audit']},
        'cloud-storage': {'cloud_token': tokens['cloud']},
        'audit': {'audit_token': tokens['audit']},
    }
    for role in [*ROLES, 'frontend']:
        folder = root / role
        folder.mkdir()
        (folder / 'ca.pem').write_bytes(ca_pem)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sans = [x509.DNSName(role), x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
        for ns in ('pattern-consumer', 'pattern-provider'):
            sans += [x509.DNSName(f'{role}.{ns}.svc.cluster.local')]
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (folder / 'server.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / 'server-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if role == 'frontend':
            continue
        cfg = {'role': role, 'ca_file': str(folder / 'ca.pem') if local else '/run/pattern/ca.pem',
               'data_dir': str(folder / 'data') if local else '/data', **configs[role]}
        (folder / 'config.json').write_text(json.dumps(cfg, indent=2), encoding='utf-8')
        for p in folder.iterdir():
            # Parent .runtime stays 0700; mounted role files must be readable by UID 10001.
            os.chmod(p, 0o644)
    (root / 'users.json').write_text(json.dumps(passwords, indent=2), encoding='utf-8')
    # CA private key is intentionally not persisted; regeneration uses a fresh empty directory.
    os.chmod(root / 'users.json', 0o600)
    dbpass, adminpass = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    (root / 'nextcloud.env').write_text('POSTGRES_PASSWORD=' + dbpass + '\nNEXTCLOUD_ADMIN_PASSWORD=' + adminpass + '\n', encoding='utf-8')
    os.chmod(root / 'nextcloud.env', 0o600)
    return passwords


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='.runtime')
    args = parser.parse_args()
    bootstrap(args.out)
    print('Created per-role configuration. Credentials are in the ignored .runtime directory.')
