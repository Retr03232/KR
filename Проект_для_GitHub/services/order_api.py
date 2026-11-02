import io
import time
import uuid
from fastapi import HTTPException
from starlette.middleware.wsgi import WSGIMiddleware
from wsgidav.dav_error import DAVError
from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection
from wsgidav.dc.base_dc import BaseDomainController
from wsgidav.wsgidav_app import WsgiDAVApp
from .common import app_base, call, b64, unb64, MAX_FILE


class RemoteIdentity(BaseDomainController):
    def get_domain_realm(self, path_info, environ):
        return 'protected-documents'

    def require_authentication(self, realm, environ):
        return True

    def supports_http_digest_auth(self):
        return False

    def basic_auth_user(self, realm, user_name, password, environ):
        auth = 'Basic ' + b64((user_name + ':' + password).encode())
        cfg = self.config['pattern_config']
        try:
            call(cfg, 'identity_url', 'policy_token', '/authorize', {'action': 'stat', 'path': '/'}, auth)
        except HTTPException as exc:
            if exc.status_code == 401:
                return False
            raise DAVError(exc.status_code)
        environ['pattern.authorization'] = auth
        return True


class Provider(DAVProvider):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def operation(self, environ, op, path, **kwargs):
        try:
            return call(self.cfg, 'security_url', 'order_token', '/operate',
                        {'op': op, 'path': path, **kwargs}, environ.get('pattern.authorization', ''))
        except HTTPException as exc:
            raise DAVError(exc.status_code)

    def get_resource_inst(self, path, environ):
        try:
            meta = self.operation(environ, 'stat', path)
        except DAVError as exc:
            if exc.value == 404:
                return None
            raise
        cls = Folder if meta['kind'] == 'dir' else File
        return cls(path or '/', environ, meta)


class Operations:
    def get_last_modified(self):
        return self.meta['modified']

    def get_creation_date(self):
        return self.meta['modified']

    def support_recursive_delete(self):
        return True

    def delete(self):
        self.provider.operation(self.environ, 'delete', self.path)
        self.remove_all_locks(recursive=True)

    def support_recursive_move(self, dest_path):
        return True

    def move_recursive(self, dest_path):
        self.provider.operation(self.environ, 'move', self.path, destination=dest_path)
        self.remove_all_locks(recursive=True)

    def copy_move_single(self, dest_path, *, is_move):
        if self.is_collection:
            self.provider.operation(self.environ, 'mkdir', dest_path)
        else:
            data = self.provider.operation(self.environ, 'get', self.path)['data']
            self.provider.operation(self.environ, 'put', dest_path, data=data, request_id=str(uuid.uuid4()))
            if is_move:
                self.delete()


class Folder(Operations, DAVCollection):
    def __init__(self, path, environ, meta):
        super().__init__(path, environ)
        self.meta = meta

    def get_member_names(self):
        return [r['path'].rsplit('/', 1)[1] for r in self.provider.operation(self.environ, 'list', self.path)['items']]

    def get_member(self, name):
        return self.provider.get_resource_inst(self.path.rstrip('/') + '/' + name, self.environ)

    def create_collection(self, name):
        self.provider.operation(self.environ, 'mkdir', self.path.rstrip('/') + '/' + name)

    def create_empty_resource(self, name):
        path = self.path.rstrip('/') + '/' + name
        # No empty version is committed before the PUT body is fully received.
        return File(path, self.environ, {'modified': time.time(), 'size': 0, 'oid': ''})


class WriteBuffer(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > MAX_FILE:
            raise DAVError(413)
        return super().write(data)

    def close(self):
        # WsgiDAV closes the stream before invoking end_write.
        self.flush()


class File(Operations, DAVNonCollection):
    def __init__(self, path, environ, meta):
        super().__init__(path, environ)
        self.meta = meta

    def get_content_length(self):
        return self.meta['size']

    def get_content_type(self):
        return 'application/octet-stream'

    def support_etag(self):
        return True

    def get_etag(self):
        return self.meta['oid'] or 'pending'

    def support_ranges(self):
        return True

    def get_content(self):
        result = self.provider.operation(self.environ, 'get', self.path)
        return io.BytesIO(unb64(result['data']))

    def begin_write(self, *, content_type=None):
        self.buffer = WriteBuffer()
        return self.buffer

    def end_write(self, *, with_errors):
        try:
            if not with_errors:
                rid = self.environ.get('HTTP_IDEMPOTENCY_KEY') or str(uuid.uuid4())
                result = self.provider.operation(self.environ, 'put', self.path,
                                                 data=b64(self.buffer.getvalue()), request_id=rid)
                self.meta.update(oid=result['id'], size=len(self.buffer.getvalue()), modified=time.time())
        finally:
            io.BytesIO.close(self.buffer)


def create_app(cfg):
    app = app_base('order-api')
    dav = WsgiDAVApp({'provider_mapping': {'/': Provider(cfg)}, 'pattern_config': cfg, 'mount_path': '/dav',
                      'http_authenticator': {'domain_controller': RemoteIdentity,
                                             'accept_basic': True, 'accept_digest': False,
                                             'default_to_digest': False},
                      'dir_browser': {'enable': False}, 'verbose': 0,
                      'logging': {'enable': False}, 'property_manager': None,
                      'lock_storage': True})
    app.mount('/dav', WSGIMiddleware(dav))
    return app
