"""Run external tools without bypassing the anonymity layer.

* C/libc tools (nmap, ...) are wrapped in proxychains4 when an anonymity mode is on.
* Static Go binaries (subfinder, amass) ignore LD_PRELOAD, so proxychains cannot
  contain them. They are therefore refused outside direct mode.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from .chain import AnonymityError, is_chained, proxychains_bin, write_conf
from .config import Settings

NOT_ANON_SAFE = {"subfinder", "amass"}


class ExternalToolError(RuntimeError):
    pass


def tool_path(name: str) -> Optional[str]:
    return shutil.which(name)


def run_tool(settings: Settings, name: str, args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    path = tool_path(name)
    if not path:
        raise ExternalToolError(f"{name} is not installed")
    mode = settings.proxy.mode
    cmd = [path, *args]
    if mode != "direct" and not is_chained():
        if name in NOT_ANON_SAFE:
            raise ExternalToolError(
                f"{name} is a static Go binary and cannot be routed through {mode}; it would leak your "
                "real IP. Use --direct, or rely on the built-in passive sources.")
        pc = proxychains_bin()
        if not pc:
            raise ExternalToolError(f"{name} would bypass the anonymity layer; install proxychains4")
        try:
            conf = write_conf(settings)
        except AnonymityError as exc:
            raise ExternalToolError(str(exc)) from exc
        cmd = [pc, "-q", "-f", str(conf), *cmd]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"{name} timed out after {timeout}s") from exc
