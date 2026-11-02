"""Explicit-context deployment of the five-service functional cluster stand."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ['order-api', 'identity-policy', 'security-crypto', 'cloud-storage', 'audit']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--context', required=True)
    parser.add_argument('--image', required=True, help='Image already available to every node, preferably repo@sha256:digest')
    parser.add_argument('--runtime', default='.runtime')
    args = parser.parse_args()
    runtime = Path(args.runtime).resolve()
    documents = list(yaml.safe_load_all((ROOT / 'deploy/kubernetes.yaml').read_text()))
    def apply(objects):
        subprocess.run(['kubectl', '--context', args.context, 'apply', '-f', '-'],
                       input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}), text=True, check=True)
    apply([d for d in documents if d['kind'] == 'Namespace'])
    configs = []
    for role in ROLES:
        folder = runtime / role
        cfg = json.loads((folder / 'config.json').read_text())
        for key, target in [('identity_url', 'identity-policy'), ('cloud_url', 'cloud-storage'),
                            ('security_url', 'security-crypto'), ('audit_url', 'audit')]:
            if key in cfg:
                ns = 'pattern-provider' if target == 'cloud-storage' else 'pattern-consumer'
                cfg[key] = f'https://{target}.{ns}.svc.cluster.local:8443'
        data = {p.name: base64.b64encode(p.read_bytes()).decode() for p in folder.iterdir() if p.is_file() and p.name != 'config.json'}
        data['config.json'] = base64.b64encode(json.dumps(cfg).encode()).decode()
        configs.append({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                        'metadata': {'name': role + '-config', 'namespace': 'pattern-provider' if role == 'cloud-storage' else 'pattern-consumer'},
                        'data': data})
    # Secret values go through stdin, never command-line arguments or a tracked YAML.
    apply(configs)
    for d in documents:
        if d['kind'] == 'Deployment':
            d['spec']['template']['spec']['containers'][0]['image'] = args.image
    apply([d for d in documents if d['kind'] != 'Namespace'])
    for role in ROLES:
        ns = 'pattern-provider' if role == 'cloud-storage' else 'pattern-consumer'
        subprocess.run(['kubectl', '--context', args.context, '-n', ns, 'rollout', 'status', 'deployment/' + role, '--timeout=180s'], check=True)


if __name__ == '__main__':
    main()
