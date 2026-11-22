"""Module registry: modules self-register with @register."""
from __future__ import annotations

from typing import Dict, List, Optional, Type

from .config import Settings
from .module_base import ReconModule

_REGISTRY: Dict[str, Type[ReconModule]] = {}


def register(cls: Type[ReconModule]) -> Type[ReconModule]:
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate module name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def all_modules() -> Dict[str, Type[ReconModule]]:
    return dict(_REGISTRY)


def select(settings: Settings, kind: str, only: Optional[List[str]] = None,
           exclude: Optional[List[str]] = None, passive_only: bool = False) -> List[Type[ReconModule]]:
    unknown = [n for n in (only or []) + (exclude or []) if n not in _REGISTRY]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}. See 'reconforge modules'.")
    chosen = []
    for name, cls in sorted(_REGISTRY.items(), key=lambda kv: (kv[1].phase, kv[0])):
        if only and name not in only:
            continue
        if exclude and name in exclude:
            continue
        if not only and not settings.module_enabled(name):
            continue
        if kind not in cls.targets:
            continue
        if passive_only and cls.active:
            continue
        chosen.append(cls)
    return chosen
