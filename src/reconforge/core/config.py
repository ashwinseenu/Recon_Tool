"""Configuration.

Precedence (highest wins):
  1. environment variables  RECONFORGE_<SECTION>__<KEY>
  2. reconforge.env         (secrets: API keys, Tor control password)
  3. local.yaml             (your overrides; `reconforge config set ...`)
  4. packaged default.yaml
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from . import paths

DEFAULT_YAML = Path(__file__).resolve().parent.parent / "data" / "default.yaml"


class TorConfig(BaseModel):
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_port: int = 9051
    control_password: str = ""
    new_circuit_per_scan: bool = True


class ProxyConfig(BaseModel):
    mode: Literal["tor", "proxy", "chain", "direct"] = "tor"
    url: str = ""


class DnsConfig(BaseModel):
    mode: Literal["auto", "doh", "system"] = "auto"
    doh_urls: List[str] = Field(default_factory=lambda: [
        "https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"])


class HttpConfig(BaseModel):
    user_agent: str = "ReconForge/2.0"
    timeout_seconds: int = 25
    max_retries: int = 2
    verify_tls: bool = True


class RateLimitConfig(BaseModel):
    default_rps: float = 2.0
    per_module: Dict[str, float] = Field(default_factory=dict)


class ScopeConfig(BaseModel):
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_cidrs: List[str] = Field(default_factory=list)
    require_allowlist: bool = True


class LimitsConfig(BaseModel):
    max_hosts: int = 150
    max_ips: int = 25
    max_web_hosts: int = 25
    lookalike_max: int = 150
    port_timeout: float = 3.0
    port_workers: int = 20
    ports: List[int] = Field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080])


class TlsConfig(BaseModel):
    check_legacy: bool = True
    max_hosts: int = 10


class OutputConfig(BaseModel):
    formats: List[str] = Field(default_factory=lambda: ["json", "html", "md"])


class WebConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8787
    allowed_hosts: List[str] = Field(default_factory=list)


class ModuleToggle(BaseModel):
    enabled: bool = True


class ApiKeys(BaseModel):
    shodan: str = ""
    virustotal: str = ""
    abuseipdb: str = ""
    otx: str = ""
    securitytrails: str = ""


def load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = val
    return out


class _YamlSource(PydanticBaseSettingsSource):
    def get_field_value(self, field, field_name):  # pragma: no cover - unused
        return None, field_name, False

    def __call__(self) -> Dict[str, Any]:
        return deep_merge(load_yaml(DEFAULT_YAML), load_yaml(paths.local_config()))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RECONFORGE_", env_nested_delimiter="__", extra="ignore")

    tor: TorConfig = Field(default_factory=TorConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    fail_closed: bool = True
    dns: DnsConfig = Field(default_factory=DnsConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    tls: TlsConfig = Field(default_factory=TlsConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    modules: Dict[str, ModuleToggle] = Field(default_factory=dict)
    api: ApiKeys = Field(default_factory=ApiKeys)

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings,
                                   dotenv_settings, file_secret_settings):
        return (init_settings, env_settings, _YamlSource(settings_cls))

    def module_enabled(self, name: str) -> bool:
        toggle = self.modules.get(name)
        return True if toggle is None else toggle.enabled


# -- env file (secrets) ---------------------------------------------------------

def read_env_file(path: Optional[Path] = None) -> Dict[str, str]:
    path = path or paths.env_file()
    out: Dict[str, str] = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_env_file_into_environ() -> None:
    """Values from reconforge.env fill unset OR empty variables (real env wins)."""
    for k, v in read_env_file().items():
        if not os.environ.get(k):
            os.environ[k] = v


def _collect_api_keys() -> ApiKeys:
    g = os.environ.get
    return ApiKeys(**{n: g(f"RECONFORGE_{n.upper()}_API_KEY", "") for n in ApiKeys.model_fields})


_cached: Optional[Settings] = None


def load_settings(reload: bool = False) -> Settings:
    global _cached
    if _cached is not None and not reload:
        return _cached
    load_env_file_into_environ()
    s = Settings()
    s.api = _collect_api_keys()
    _cached = s
    return s


def reset_settings() -> None:
    global _cached
    _cached = None


# -- editing local.yaml -----------------------------------------------------------

def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    paths.secure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _set_dotted(d: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
        if not isinstance(d, dict):
            raise ValueError(f"'{p}' is not a section")
    d[parts[-1]] = value


def update_local_config(dotted: str, value: Any) -> None:
    """Set one key in local.yaml after validating the merged result."""
    path = paths.local_config()
    local = load_yaml(path)
    _set_dotted(local, dotted, value)
    try:
        Settings.model_validate(deep_merge(load_yaml(DEFAULT_YAML), local))
    except ValidationError as exc:
        raise ValueError(str(exc.errors()[0].get("msg", exc))) from exc
    _atomic_write(path, yaml.safe_dump(local, sort_keys=True))
    reset_settings()


def mutate_local_list(dotted: str, item: str, add: bool = True) -> List[str]:
    """Add/remove an item of a list-valued key (used for scope)."""
    current = list(load_yaml(paths.local_config()).get(dotted.split(".")[0], {}).get(dotted.split(".")[1], []))
    if add and item not in current:
        current.append(item)
    if not add:
        current = [c for c in current if c != item]
    update_local_config(dotted, current)
    return current


def masked(settings: Settings) -> dict:
    d = settings.model_dump()
    if d["tor"]["control_password"]:
        d["tor"]["control_password"] = "********"
    d["api"] = {k: ("set" if v else "") for k, v in d["api"].items()}
    return d
