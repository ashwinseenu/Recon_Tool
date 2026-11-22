"""Importing this package registers every built-in module.

Drop a new file here that subclasses ReconModule and uses @register; it is
picked up automatically. Add a toggle under `modules:` in the config to make it
switchable (modules without a toggle are enabled).
"""
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules

for _m in iter_modules([str(Path(__file__).parent)]):
    if not _m.name.startswith("_"):
        import_module(f"{__name__}.{_m.name}")
