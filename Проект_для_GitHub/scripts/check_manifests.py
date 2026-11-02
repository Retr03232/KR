from pathlib import Path
import yaml
from generate_deploy import generate, ROLES, EDGES, NS

root = Path(__file__).resolve().parents[1]
paths = [root / 'compose.yaml', root / 'compose.nextcloud.yaml', *sorted((root / 'deploy').glob('*'))]
before = {p: p.read_bytes() for p in paths if p.is_file()}
generate()
assert all(p.read_bytes() == data for p, data in before.items()), 'Generated manifest drift'
docs = list(yaml.safe_load_all((root / 'deploy/kubernetes.yaml').read_text()))
deployments = {d['metadata']['name']: d for d in docs if d['kind'] == 'Deployment'}
assert set(deployments) == set(ROLES)
assert not any(d['kind'] == 'Secret' for d in docs), 'Credentials must not be in tracked manifests'
for role, deployment in deployments.items():
    assert deployment['metadata']['namespace'] == NS[role]
    pod = deployment['spec']['template']['spec']
    assert deployment['spec']['replicas'] == 1 and pod['securityContext']['runAsNonRoot']
    assert not pod['automountServiceAccountToken']
policies = {(d['metadata']['namespace'], d['metadata']['name']): d['spec'] for d in docs if d['kind'] == 'NetworkPolicy'}
for ns in set(NS.values()):
    assert policies[(ns, 'default-deny')]['policyTypes'] == ['Ingress', 'Egress']
for source, target in EDGES:
    egress = policies[(NS[source], source)]['egress']
    ingress = policies[(NS[target], target)]['ingress']
    assert any(rule['to'][0].get('podSelector', {}).get('matchLabels', {}).get('app') == target for rule in egress)
    assert any(rule['from'][0]['podSelector']['matchLabels']['app'] == source for rule in ingress)
cloud = policies[(NS['cloud-storage'], 'cloud-storage')]
assert all('ports' in rule and rule['ports'][0]['port'] == 53 for rule in cloud['egress'])
print('Manifest checks passed: five deployments, role-scoped volumes, default deny and required network edges.')
print('This is structural validation, not Kubernetes admission or a running-cluster test.')
