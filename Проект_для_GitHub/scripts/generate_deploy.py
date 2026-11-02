"""Generate reviewable Compose and Kubernetes manifests without deploying."""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ['order-api', 'identity-policy', 'security-crypto', 'cloud-storage', 'audit']
NS = {r: 'pattern-provider' if r == 'cloud-storage' else 'pattern-consumer' for r in ROLES}
EDGES = [('order-api', 'identity-policy'), ('order-api', 'security-crypto'),
         ('security-crypto', 'identity-policy'), ('security-crypto', 'cloud-storage'), ('security-crypto', 'audit')]


def generate():
    services, networks, volumes = {}, {}, {}
    for r in ROLES:
        nets = [f'link-{i}' for i, edge in enumerate(EDGES) if r in edge] + ['monitoring']
        for n in nets:
            networks[n] = {'internal': True}
        if r == 'order-api':
            nets += ['frontend']
            networks['frontend'] = {}
        volumes[r + '-data'] = {}
        services[r] = {'build': '.', 'image': 'course-pattern:0.1.0', 'init': True,
                       'restart': 'unless-stopped', 'read_only': True, 'cap_drop': ['ALL'],
                       'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp:size=32m'],
                       'volumes': [f'./.runtime/{r}:/run/pattern:ro', f'{r}-data:/data'],
                       'networks': nets,
                       'healthcheck': {'test': ['CMD', 'python', '-c',
                           "import ssl,urllib.request; urllib.request.urlopen('https://localhost:8443/health',context=ssl.create_default_context(cafile='/run/pattern/ca.pem'))"],
                           'interval': '15s', 'timeout': '5s', 'retries': 3},
                       'mem_limit': '768m' if r == 'security-crypto' else '512m'}
    services['order-api']['ports'] = ['127.0.0.1:8444:8443']
    compose = {'name': 'course-pattern', 'services': services, 'networks': networks, 'volumes': volumes}
    (ROOT / 'compose.yaml').write_text(yaml.safe_dump(compose, sort_keys=False), encoding='utf-8', newline='\n')
    extra = {'services': {
        'nextcloud': {'image': 'nextcloud:33-apache', 'profiles': ['nextcloud'],
                     'env_file': ['.runtime/nextcloud.env'],
                     'environment': {'POSTGRES_HOST': 'nextcloud-db', 'POSTGRES_DB': 'nextcloud', 'POSTGRES_USER': 'nextcloud',
                                     'NEXTCLOUD_ADMIN_USER': 'admin', 'NEXTCLOUD_TRUSTED_DOMAINS': 'localhost 127.0.0.1',
                                     'OVERWRITEPROTOCOL': 'https'},
                     'entrypoint': ['/bin/sh', '/pattern-entrypoint.sh'],
                     'command': ['apache2-foreground'],
                     'volumes': ['nextcloud-data:/var/www/html', './.runtime/ca.pem:/tmp/pattern-ca.pem:ro',
                                 './deploy/nextcloud-entrypoint.sh:/pattern-entrypoint.sh:ro'],
                     'networks': ['frontend', 'nextcloud-db'], 'depends_on': ['nextcloud-db']},
        'nextcloud-db': {'image': 'postgres:16-alpine', 'profiles': ['nextcloud'],
                         'env_file': ['.runtime/nextcloud.env'],
                         'environment': {'POSTGRES_DB': 'nextcloud', 'POSTGRES_USER': 'nextcloud'},
                         'volumes': ['nextcloud-db:/var/lib/postgresql/data'], 'networks': ['nextcloud-db']},
        'frontend': {'image': 'caddy:2-alpine', 'profiles': ['nextcloud'],
                     'volumes': ['./deploy/Caddyfile:/etc/caddy/Caddyfile:ro', './.runtime/frontend:/certs:ro'],
                     'ports': ['127.0.0.1:8443:443'], 'networks': ['frontend'], 'depends_on': ['nextcloud']},
        'prometheus': {'image': 'prom/prometheus:v3.5.0', 'profiles': ['monitoring'],
                        'volumes': ['./deploy/prometheus.yaml:/etc/prometheus/prometheus.yml:ro', './.runtime/ca.pem:/etc/prometheus/pattern-ca.pem:ro'],
                        'ports': ['127.0.0.1:9090:9090'], 'networks': ['monitoring', 'monitoring-ui']}},
        'networks': {'nextcloud-db': {'internal': True}, 'monitoring-ui': {}},
        'volumes': {'nextcloud-data': {}, 'nextcloud-db': {}}}
    (ROOT / 'compose.nextcloud.yaml').write_text(yaml.safe_dump(extra, sort_keys=False), encoding='utf-8', newline='\n')
    deploy = ROOT / 'deploy'
    deploy.mkdir(exist_ok=True)
    (deploy / 'Caddyfile').write_text(':443 {\n  tls /certs/server.pem /certs/server-key.pem\n  reverse_proxy nextcloud:80\n}\n', encoding='utf-8', newline='\n')
    (deploy / 'prometheus.yaml').write_text(yaml.safe_dump({'global': {'scrape_interval': '15s'}, 'scrape_configs': [
        {'job_name': r, 'scheme': 'https', 'tls_config': {'ca_file': '/etc/prometheus/pattern-ca.pem'},
         'static_configs': [{'targets': [r + ':8443']}]} for r in ROLES]}, sort_keys=False), encoding='utf-8', newline='\n')
    manifests = []
    for ns in sorted(set(NS.values())):
        manifests += [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns}},
                      {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                       'metadata': {'name': 'default-deny', 'namespace': ns},
                       'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}}]
    def selector(role):
        return {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NS.get(role, 'pattern-consumer')}},
                'podSelector': {'matchLabels': {'app': role}}}
    port = [{'protocol': 'TCP', 'port': 8443}]
    for role in ROLES:
        ns = NS[role]
        meta = {'name': role, 'namespace': ns}
        container = {'name': role, 'image': 'course-pattern:0.1.0', 'imagePullPolicy': 'IfNotPresent',
                     'ports': [{'containerPort': 8443}],
                     'env': [{'name': 'PATTERN_CONFIG', 'value': '/run/pattern/config.json'}],
                     'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                         'capabilities': {'drop': ['ALL']}},
                     'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                                   'limits': {'cpu': '1', 'memory': '768Mi' if role == 'security-crypto' else '512Mi'}},
                     'volumeMounts': [{'name': 'config', 'mountPath': '/run/pattern', 'readOnly': True},
                                      {'name': 'data', 'mountPath': '/data'}, {'name': 'tmp', 'mountPath': '/tmp'}],
                     'readinessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/health', 'port': 8443}, 'initialDelaySeconds': 3},
                     'livenessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/health', 'port': 8443}, 'initialDelaySeconds': 15}}
        manifests += [
            {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': meta,
             'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Gi'}}}},
            {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': meta,
             'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': role}},
                      'template': {'metadata': {'labels': {'app': role}}, 'spec': {
                          'automountServiceAccountToken': False,
                          'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
                                              'fsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}},
                          'containers': [container], 'volumes': [
                              {'name': 'config', 'secret': {'secretName': role + '-config', 'defaultMode': 288}},
                              {'name': 'data', 'persistentVolumeClaim': {'claimName': role}},
                              {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}}]}}}},
            {'apiVersion': 'v1', 'kind': 'Service', 'metadata': meta,
             'spec': {'selector': {'app': role}, 'ports': [{'port': 8443, 'targetPort': 8443}]}},
        ]
        incoming = [a for a, b in EDGES if b == role] + (['nextcloud'] if role == 'order-api' else [])
        ingress = [{'from': [selector(source)], 'ports': port} for source in incoming + ['prometheus']]
        egress = [{'to': [selector(b)], 'ports': port} for a, b in EDGES if a == role]
        egress += [{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                            'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                    'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]}]
        manifests.append({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': meta,
                          'spec': {'podSelector': {'matchLabels': {'app': role}}, 'policyTypes': ['Ingress', 'Egress'],
                                   'ingress': ingress, 'egress': egress}})
    (deploy / 'kubernetes.yaml').write_text(yaml.safe_dump_all(manifests, sort_keys=False), encoding='utf-8', newline='\n')


if __name__ == '__main__':
    generate()
