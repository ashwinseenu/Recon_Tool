"""ReconForge command line."""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__
from . import modules as _modules  # noqa: F401  (registers modules)
from .core import config as cfg
from .core import keystore, paths, registry
from .core.chain import AnonymityError, ensure_chained, proxychains_bin
from .core.engine import run_scan
from .core.models import SEVERITY_ORDER
from .core.netclient import check_egress, new_tor_circuit, tor_reachable
from .core.scope import scope_empty, summarize_scope
from .reporting import report as rpt

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="ReconForge - attack-surface & infrastructure OSINT for Linux (Tor/proxy aware, scope-gated).")
keys_app = typer.Typer(no_args_is_help=True, help="Manage API keys.")
scope_app = typer.Typer(no_args_is_help=True, help="Manage the authorised scope for active modules.")
config_app = typer.Typer(no_args_is_help=True, help="Inspect and change configuration.")
report_app = typer.Typer(no_args_is_help=True, help="List, view and export saved reports.")
app.add_typer(keys_app, name="keys")
app.add_typer(scope_app, name="scope")
app.add_typer(config_app, name="config")
app.add_typer(report_app, name="report")
console = Console()

SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "green", "info": "cyan"}
SUPPORTED = {"debian": 11, "ubuntu": 22, "rhel": 8, "rocky": 8, "almalinux": 8, "centos": 8, "ol": 8, "kali": 0, "parrot": 0}


def _fail(msg: str, code: int = 1) -> "typer.Exit":
    console.print(Panel(escape(msg), border_style="red", title="Error"))
    return typer.Exit(code=code)


def _add_scope_items(settings: cfg.Settings, items: List[str]) -> None:
    for s in items:
        try:
            ipaddress.ip_network(s, strict=False)
            settings.scope.allowed_cidrs.append(s)
        except ValueError:
            settings.scope.allowed_domains.append(s)


# ----------------------------------------------------------------------------- scan

@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or IP address to assess."),
    module: Optional[List[str]] = typer.Option(None, "--module", "-m", help="Run only these modules (repeatable)."),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", "-x", help="Skip these modules (repeatable)."),
    passive_only: bool = typer.Option(False, "--passive-only", help="Never touch the target: skip every active module."),
    scope: Optional[List[str]] = typer.Option(None, "--scope", help="Authorise a domain/CIDR for this run only (repeatable)."),
    direct: bool = typer.Option(False, "--direct", help="Disable the anonymity layer for this run."),
    workers: int = typer.Option(6, "--workers", min=1, max=32, help="Modules run in parallel within a phase."),
    fmt: Optional[List[str]] = typer.Option(None, "--format", "-f", help="Report formats: json, html, md, csv."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 2 if any finding is at/above this severity."),
):
    """Run a scan and write reports."""
    settings = cfg.load_settings(reload=True)
    if direct:
        settings.proxy.mode, settings.fail_closed = "direct", False
    if scope:
        _add_scope_items(settings, scope)
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise _fail(f"--fail-on must be one of: {', '.join(SEVERITY_ORDER)}")
    try:
        ensure_chained(settings, sys.argv[1:])      # chain mode re-executes under proxychains
        console.print(f"[bold]ReconForge {__version__}[/]  target [cyan]{escape(target)}[/]  mode [magenta]{settings.proxy.mode}[/]")
        console.print(f"[dim]scope: {escape(summarize_scope(settings.scope))}[/]")
        if not passive_only and scope_empty(settings.scope):
            console.print("[yellow]Scope is empty: active modules will be skipped. Add targets with "
                          "'reconforge scope add <domain|cidr>'.[/]")

        def progress(name: str, status: str, detail: str) -> None:
            if status == "start":
                return
            mark = {"done": "[green]ok  [/]", "skip": "[yellow]skip[/]", "error": "[red]err [/]"}[status]
            console.print(f"  {mark} {name}" + (f"  [dim]{escape(detail[:90])}[/]" if detail else ""))

        report = run_scan(target, settings, only=module, exclude=exclude, passive_only=passive_only,
                          max_workers=workers, progress=progress)
    except (AnonymityError, ValueError) as exc:
        raise _fail(str(exc))

    rep = report.to_dict()
    e = rep["egress"]
    if e.get("mode") != "direct":
        console.print(f"[dim]egress {e.get('egress_ip')}  tor={e.get('is_tor')}  {e.get('detail')}[/]")
    _print_findings(rep)
    formats = list(fmt) if fmt else settings.output.formats
    written = rpt.write_report(report, formats)
    console.print("\n[bold]Reports[/]")
    for k, p in written.items():
        console.print(f"  {k:<5} {p}")
    if fail_on and any(SEVERITY_ORDER[s] >= SEVERITY_ORDER[fail_on] and n for s, n in rep["severity_counts"].items()):
        raise typer.Exit(code=2)


def _print_findings(rep: dict) -> None:
    notable = [f for f in rpt.all_findings(rep) if f["severity"] != "info"]
    sc = rep["severity_counts"]
    console.print("\n" + "  ".join(f"[{SEV_STYLE[k]}]{k} {v}[/]" for k, v in reversed(list(sc.items()))))
    console.print(f"[dim]{len(rep['assets']['hostnames'])} hostnames, {len(rep['assets']['ips'])} IPs, "
                  f"{rep['finding_count']} findings in {rep['duration']}s[/]")
    if not notable:
        return
    t = Table(show_lines=False, pad_edge=False)
    t.add_column("Severity")
    t.add_column("Finding", overflow="fold")
    t.add_column("Module")
    for f in notable[:40]:
        t.add_row(f"[{SEV_STYLE[f['severity']]}]{f['severity']}[/]", escape(f["title"]), f["module"])
    console.print(t)
    if len(notable) > 40:
        console.print(f"[dim]... and {len(notable) - 40} more in the report[/]")


# ----------------------------------------------------------------------------- info

@app.command("modules")
def list_modules():
    """List modules, their phase and requirements."""
    settings = cfg.load_settings()
    t = Table(title="Modules")
    for c in ("Name", "Phase", "Type", "Targets", "Needs", "On", "Description"):
        t.add_column(c, overflow="fold")
    for name, cls in sorted(registry.all_modules().items(), key=lambda kv: (kv[1].phase, kv[0])):
        needs = cls.requires_key and f"key:{cls.requires_key}" or cls.external_tool and f"bin:{cls.external_tool}" or \
            (cls.optional_key and f"opt-key:{cls.optional_key}") or "-"
        t.add_row(name, str(cls.phase), "[magenta]active[/]" if cls.active else "passive", ",".join(sorted(cls.targets)),
                  needs, "yes" if settings.module_enabled(name) else "no", cls.description)
    console.print(t)


@app.command()
def check():
    """Verify the anonymity layer: egress IP and Tor status."""
    settings = cfg.load_settings(reload=True)
    try:
        ensure_chained(settings, sys.argv[1:])
        st = check_egress(settings)
    except AnonymityError as exc:
        raise _fail(str(exc))
    color = "green" if st.ok else "red"
    console.print(Panel(f"Mode: {st.mode}\nEgress IP: [{color}]{st.egress_ip}[/]\nVia Tor: {st.is_tor}\n{escape(st.detail)}",
                        title="Egress check", border_style=color))
    raise typer.Exit(code=0 if st.ok else 1)


@app.command()
def newid():
    """Request a fresh Tor circuit (NEWNYM)."""
    ok = new_tor_circuit(cfg.load_settings(reload=True))
    console.print("[green]New Tor identity requested.[/]" if ok else
                  "[yellow]Could not signal Tor (control port unreachable or wrong password). Run 'reconforge doctor'.[/]")
    raise typer.Exit(code=0 if ok else 1)


@app.command()
def doctor(net: bool = typer.Option(False, "--net", help="Also run the live egress check.")):
    """Diagnose the installation: OS, Python, Tor, tools, keys, scope."""
    s = cfg.load_settings(reload=True)
    rows = []

    def add(name: str, state: str, detail: str) -> None:
        rows.append((name, state, detail))

    osr = {}
    p = Path("/etc/os-release")
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                osr[k] = v.strip('"')
    oid, ver = osr.get("ID", "?"), osr.get("VERSION_ID", "?")
    major = int(ver.split(".")[0]) if ver.split(".")[0].isdigit() else 0
    fam = oid if oid in SUPPORTED else next((x for x in osr.get("ID_LIKE", "").split() if x in SUPPORTED), "")
    ok_os = platform.system() == "Linux" and fam != "" and major >= SUPPORTED.get(fam, 0)
    add("Operating system", "OK" if ok_os else "WARN", f"{osr.get('PRETTY_NAME', platform.platform())} (supported: Debian 11+, Ubuntu 22.04+, RHEL/Rocky/Alma 8+)")
    add("Python", "OK" if sys.version_info >= (3, 9) else "FAIL", platform.python_version())
    add("Config dir", "OK", str(paths.config_dir()))
    add("Data dir", "OK" if os.access(paths.data_dir().parent, os.W_OK) or paths.data_dir().exists() else "WARN", str(paths.data_dir()))
    envp = paths.env_file()
    if envp.exists():
        mode = envp.stat().st_mode & 0o777
        add("Secrets file", "OK" if mode & 0o077 == 0 else "WARN", f"{envp} mode {oct(mode)[2:]}" + ("" if mode & 0o077 == 0 else " (should be 600)"))
    else:
        add("Secrets file", "INFO", f"{envp} not created yet (created by 'reconforge keys set')")
    mode = s.proxy.mode
    add("Proxy mode", "OK" if mode != "direct" else "WARN", f"{mode}  (fail_closed={s.fail_closed}, dns={s.dns.mode})")
    if mode in ("tor", "chain"):
        up = tor_reachable(s)
        add("Tor SOCKS", "OK" if up else "FAIL", f"{s.tor.socks_host}:{s.tor.socks_port} " + ("reachable" if up else "not listening - start Tor (systemctl enable --now tor)"))
        if up:
            add("Tor control", "OK" if new_tor_circuit(s) else "WARN",
                f"{s.tor.socks_host}:{s.tor.control_port} " + ("accepted NEWNYM" if True else ""))
    if mode in ("chain",) or mode != "direct":
        add("proxychains4", "OK" if proxychains_bin() else ("FAIL" if mode == "chain" else "INFO"),
            proxychains_bin() or "not installed (needed for chain mode and anonymised nmap)")
    for tool, why in (("nmap", "service detection"), ("subfinder", "optional, --direct only"), ("amass", "optional, --direct only")):
        add(tool, "OK" if shutil.which(tool) else "INFO", shutil.which(tool) or f"not installed ({why})")
    configured = [k for k, v in keystore.status().items() if v["configured"]]
    add("API keys", "OK" if configured else "INFO", ", ".join(configured) or "none set (keyless modules still work)")
    add("Scope", "OK" if not scope_empty(s.scope) else "WARN",
        summarize_scope(s.scope) + ("" if not scope_empty(s.scope) else "  -> active modules will be skipped"))
    if net:
        try:
            st = check_egress(s)
            add("Egress", "OK" if st.ok else "FAIL", f"{st.egress_ip} tor={st.is_tor} {st.detail}")
        except AnonymityError as exc:
            add("Egress", "FAIL", str(exc))
    t = Table(title=f"ReconForge {__version__} doctor")
    for c in ("Check", "Result", "Detail"):
        t.add_column(c, overflow="fold")
    style = {"OK": "green", "WARN": "yellow", "FAIL": "bold red", "INFO": "cyan"}
    for n, st_, d in rows:
        t.add_row(n, f"[{style[st_]}]{st_}[/]", escape(d))
    console.print(t)
    raise typer.Exit(code=1 if any(r[1] == "FAIL" for r in rows) else 0)


# ----------------------------------------------------------------------------- keys

@keys_app.command("list")
def keys_list():
    """Show configured keys (masked)."""
    t = Table(title="API keys")
    for c in ("Service", "Status", "Value", "Source", "Get a key"):
        t.add_column(c, overflow="fold")
    for name, st in keystore.status().items():
        t.add_row(name, "[green]configured[/]" if st["configured"] else "[yellow]missing[/]", st["masked"] or "-", st["source"] or "-", st["url"])
    console.print(t)


@keys_app.command("set")
def keys_set(service: str = typer.Argument(..., help="shodan|virustotal|abuseipdb|otx|securitytrails"),
             value: Optional[str] = typer.Option(None, "--value", help="Key (omit to be prompted with hidden input).")):
    """Store an API key (reconforge.env, mode 600)."""
    if value is None:
        value = typer.prompt(f"{service} API key", hide_input=True)
    try:
        keystore.set_key(service, value)
    except ValueError as exc:
        raise _fail(str(exc))
    console.print(f"[green]Saved {service} key[/] ({keystore.mask(value.strip())})")


@keys_app.command("unset")
def keys_unset(service: str):
    """Remove an API key."""
    try:
        keystore.unset_key(service)
    except ValueError as exc:
        raise _fail(str(exc))
    console.print(f"[yellow]Removed {service} key[/]")


@keys_app.command("setup")
def keys_setup():
    """Interactive wizard for all services (Enter skips)."""
    for name, st in keystore.status().items():
        cur = f" (current {st['masked']})" if st["configured"] else ""
        console.print(f"\n[bold]{name}[/]{cur}  {st['url']}")
        val = typer.prompt("  key", default="", hide_input=True, show_default=False)
        if val.strip():
            try:
                keystore.set_key(name, val)
                console.print("  [green]saved[/]")
            except ValueError as exc:
                console.print(f"  [red]{exc}[/]")
    keys_list()


# ----------------------------------------------------------------------------- scope

@scope_app.command("show")
def scope_show():
    """Show the authorised scope."""
    s = cfg.load_settings(reload=True).scope
    console.print(f"domains: {', '.join(s.allowed_domains) or '(none)'}\ncidrs:   {', '.join(s.allowed_cidrs) or '(none)'}\n"
                  f"require_allowlist: {s.require_allowlist}")


@scope_app.command("add")
def scope_add(items: List[str] = typer.Argument(..., help="Domains and/or CIDRs you are authorised to test.")):
    """Authorise domains/CIDRs for active modules (saved to local.yaml)."""
    for item in items:
        try:
            ipaddress.ip_network(item, strict=False)
            cfg.mutate_local_list("scope.allowed_cidrs", item, True)
        except ValueError:
            cfg.mutate_local_list("scope.allowed_domains", item.strip().lower().lstrip("*."), True)
    console.print("[green]Scope updated.[/]")
    scope_show()


@scope_app.command("remove")
def scope_remove(items: List[str] = typer.Argument(...)):
    """Remove domains/CIDRs from the scope."""
    for item in items:
        cfg.mutate_local_list("scope.allowed_cidrs", item, False)
        cfg.mutate_local_list("scope.allowed_domains", item.strip().lower(), False)
    scope_show()


# ----------------------------------------------------------------------------- config

@config_app.command("show")
def config_show():
    """Print the effective configuration (secrets masked)."""
    console.print(yaml.safe_dump(cfg.masked(cfg.load_settings(reload=True)), sort_keys=False))


@config_app.command("path")
def config_path():
    """Print where configuration, secrets and data live."""
    console.print(f"config dir : {paths.config_dir()}\nlocal.yaml : {paths.local_config()}\n"
                  f"secrets    : {paths.env_file()}\ndata dir   : {paths.data_dir()}\nreports    : {paths.data_dir() / 'results'}")


@config_app.command("set")
def config_set(key: str = typer.Argument(..., help="Dotted key, e.g. proxy.mode"),
               value: str = typer.Argument(..., help="YAML value, e.g. chain, 9050, true, '[80,443]'")):
    """Set a configuration value, e.g.  config set proxy.mode proxy  /  config set proxy.url socks5://host:1080"""
    if key.startswith("tor.control_password"):
        keystore.set_env_var("RECONFORGE_TOR__CONTROL_PASSWORD", value)
        console.print("[green]Stored in the secrets file.[/]")
        return
    try:
        cfg.update_local_config(key, yaml.safe_load(value))
    except ValueError as exc:
        raise _fail(f"Invalid value for {key}: {exc}")
    console.print(f"[green]{key} = {value}[/]")


# ----------------------------------------------------------------------------- reports

@report_app.command("list")
def report_list(limit: int = 20):
    """List saved reports."""
    t = Table(title="Reports")
    for c in ("Scan ID", "Target", "Findings", "crit/high/med"):
        t.add_column(c)
    for r in rpt.list_reports(limit):
        sv = r["severity"]
        t.add_row(r["scan_id"], r["target"], str(r["findings"]), f"{sv['critical']}/{sv['high']}/{sv['medium']}")
    console.print(t)


@report_app.command("show")
def report_show(scan_id: str):
    """Print the findings of a saved report."""
    try:
        _print_findings(rpt.load_report(scan_id))
    except (FileNotFoundError, ValueError):
        raise _fail(f"No such report: {scan_id}")


@report_app.command("export")
def report_export(scan_id: str, fmt: str = typer.Option("html", "--format", "-f", help="json|html|md|csv"),
                  out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write to this file instead of stdout.")):
    """Re-export a saved report in another format."""
    if fmt not in rpt.RENDERERS:
        raise _fail(f"format must be one of: {', '.join(rpt.RENDERERS)}")
    try:
        text = rpt.RENDERERS[fmt](rpt.load_report(scan_id))
    except (FileNotFoundError, ValueError):
        raise _fail(f"No such report: {scan_id}")
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote {out}[/]")
    else:
        typer.echo(text)


# ----------------------------------------------------------------------------- web

@app.command()
def serve(host: Optional[str] = typer.Option(None, help="Bind address (default 127.0.0.1)."),
          port: Optional[int] = typer.Option(None, help="Port (default 8787).")):
    """Start the local web dashboard (token-protected)."""
    import uvicorn

    from .web.app import ensure_token

    s = cfg.load_settings(reload=True)
    try:
        ensure_chained(s, sys.argv[1:])
    except AnonymityError as exc:
        raise _fail(str(exc))
    h, p = host or s.web.host, port or s.web.port
    token = ensure_token()
    shown = "127.0.0.1" if h in ("0.0.0.0", "::") else h
    console.print(Panel(f"Dashboard: [bold]http://{shown}:{p}/?token={token}[/]\n"
                        "Open that link once; your browser then keeps a session cookie.", title="ReconForge", border_style="green"))
    if h not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]Bound beyond localhost: put TLS and a firewall in front of this.[/]")
    uvicorn.run("reconforge.web.app:app", host=h, port=p, log_level="warning")


@app.command()
def version():
    """Print the version."""
    console.print(__version__)


def main() -> None:
    try:
        app()
    except AnonymityError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
