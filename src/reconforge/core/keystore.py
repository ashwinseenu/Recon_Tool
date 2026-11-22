"""API key and secret storage (reconforge.env, mode 0600)."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Optional

from . import paths
from .config import ApiKeys, _atomic_write, read_env_file, reset_settings

# service -> (env var, where to get a key)
SERVICES: Dict[str, tuple] = {
    "shodan": ("RECONFORGE_SHODAN_API_KEY", "https://account.shodan.io"),
    "virustotal": ("RECONFORGE_VIRUSTOTAL_API_KEY", "https://www.virustotal.com/gui/my-apikey"),
    "abuseipdb": ("RECONFORGE_ABUSEIPDB_API_KEY", "https://www.abuseipdb.com/account/api"),
    "otx": ("RECONFORGE_OTX_API_KEY", "https://otx.alienvault.com/api"),
    "securitytrails": ("RECONFORGE_SECURITYTRAILS_API_KEY", "https://securitytrails.com/app/account/credentials"),
}
assert set(SERVICES) == set(ApiKeys.model_fields)

_VALID = re.compile(r"^[A-Za-z0-9_\-\.=+/:]{8,256}$")
_LINE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=")


class KeyError_(ValueError):
    pass


def mask(value: str) -> str:
    if not value:
        return ""
    return "*" * len(value) if len(value) <= 8 else f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def set_env_var(var: str, value: Optional[str], path: Optional[Path] = None) -> None:
    """Set (or remove, when value is None) one variable, preserving other lines."""
    path = path or paths.env_file()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    out, found = [], False
    for line in lines:
        m = _LINE.match(line)
        if m and m.group(1) == var and not line.lstrip().startswith("#"):
            found = True
            if value is not None:
                out.append(f"{var}={value}")
            continue
        out.append(line)
    if not found and value is not None:
        out.append(f"{var}={value}")
    _atomic_write(path, "\n".join(out) + "\n", 0o600)
    if value is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = value
    reset_settings()


def _service(name: str) -> tuple:
    name = name.lower().strip()
    if name not in SERVICES:
        raise KeyError_(f"Unknown service '{name}'. Choose from: {', '.join(SERVICES)}")
    return SERVICES[name]


def set_key(service: str, value: str) -> None:
    var, _ = _service(service)
    value = value.strip()
    if not _VALID.match(value):
        raise KeyError_("Key looks invalid (8-256 characters: letters, digits and _ - . = + / :).")
    set_env_var(var, value)


def unset_key(service: str) -> None:
    var, _ = _service(service)
    set_env_var(var, None)


def status() -> Dict[str, dict]:
    file_vals = read_env_file()
    out = {}
    for name, (var, url) in SERVICES.items():
        env_val = os.environ.get(var, "")
        val = env_val or file_vals.get(var, "")
        source = "" if not val else ("environment" if env_val and env_val != file_vals.get(var) else "env file")
        out[name] = {"var": var, "configured": bool(val), "masked": mask(val), "source": source, "url": url}
    return out
