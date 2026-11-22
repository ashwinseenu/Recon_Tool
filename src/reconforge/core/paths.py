"""Filesystem locations.

Defaults follow XDG (~/.config/reconforge, ~/.local/share/reconforge) and are
overridable with RECONFORGE_CONFIG_DIR / RECONFORGE_DATA_DIR, which is how the
system-wide install (/etc/reconforge, /var/lib/reconforge) and Docker work.
"""
from __future__ import annotations

import os
from pathlib import Path


def _base(env_var: str, xdg_var: str, fallback: str) -> Path:
    override = os.environ.get(env_var)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get(xdg_var)
    root = Path(xdg) if xdg else Path.home() / fallback
    return root / "reconforge"


def config_dir() -> Path:
    return _base("RECONFORGE_CONFIG_DIR", "XDG_CONFIG_HOME", ".config")


def data_dir() -> Path:
    return _base("RECONFORGE_DATA_DIR", "XDG_DATA_HOME", ".local/share")


def secure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create `path` (private by default); never loosen an existing directory."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        try:
            path.chmod(mode)
        except OSError:
            pass
    return path


def results_dir() -> Path:
    return secure_dir(data_dir() / "results")


def run_dir() -> Path:
    return secure_dir(data_dir() / "run")


def env_file() -> Path:
    """Secrets file (API keys, Tor control password). Always mode 0600."""
    return config_dir() / "reconforge.env"


def local_config() -> Path:
    return config_dir() / "local.yaml"
