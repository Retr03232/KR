import importlib
from .common import settings

cfg = settings()
module = importlib.import_module('services.' + cfg['role'].replace('-', '_'))
app = module.create_app(cfg)
