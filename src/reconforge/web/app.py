"""Local web dashboard.

Security model: the dashboard can start scans and store API keys, so it is not
open to "anyone on localhost". Access needs a random token (cookie, header or
?token= once), Host headers are checked against DNS-rebinding, and POSTs must
come from the same origin.
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import modules as _modules  # noqa: F401
from ..core import config as cfg
from ..core import keystore, paths, registry
from ..core.chain import AnonymityError
from ..core.engine import run_scan
from ..core.netclient import check_egress
from ..core.scope import scope_empty
from ..reporting import report as rpt

HERE = Path(__file__).parent
COOKIE = "rf_session"
_LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def ensure_token() -> str:
    env = os.environ.get("RECONFORGE_WEB__TOKEN")
    if env:
        return env
    p = paths.run_dir() / "web.token"
    if p.exists():
        return p.read_text().strip()
    token = secrets.token_urlsafe(32)
    p.write_text(token)
    p.chmod(0o600)
    return token


def create_app() -> FastAPI:
    app = FastAPI(title="ReconForge", docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    jobs: Dict[str, dict] = {}
    lock = threading.Lock()
    seq = [0]

    @app.middleware("http")
    async def guard(request: Request, call_next):
        settings = cfg.load_settings()
        host = (request.headers.get("host") or "").rsplit(":", 1)[0] if not (request.headers.get("host") or "").startswith("[") \
            else (request.headers.get("host") or "").split("]")[0] + "]"
        bound_loopback = settings.web.host in ("127.0.0.1", "localhost", "::1")
        allowed = _LOOPBACK | set(settings.web.allowed_hosts)
        if bound_loopback and host not in allowed:
            return PlainTextResponse("Forbidden: unexpected Host header", status_code=403)
        if request.url.path.startswith("/static/"):
            return await call_next(request)
        token = ensure_token()
        supplied = request.query_params.get("token") or request.headers.get("x-reconforge-token") or ""
        if supplied and hmac.compare_digest(supplied, token):
            if request.query_params.get("token"):          # exchange the URL token for a cookie, then drop it from the URL
                resp = RedirectResponse(url=request.url.path or "/", status_code=303)
                resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=86400 * 7)
                return resp
        elif not hmac.compare_digest(request.cookies.get(COOKIE, ""), token):
            return PlainTextResponse("Unauthorized. Open the link printed by 'reconforge serve' "
                                     "(http://127.0.0.1:8787/?token=...).", status_code=401)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and urlparse(origin).netloc != request.headers.get("host"):
                return PlainTextResponse("Forbidden: cross-origin request", status_code=403)
        return await call_next(request)

    # -- jobs -------------------------------------------------------------------
    def run_job(job_id: str, target: str, only: Optional[List[str]], passive_only: bool) -> None:
        settings = cfg.load_settings(reload=True)

        def progress(name: str, status: str, detail: str) -> None:
            with lock:
                jobs[job_id]["modules"][name] = status

        with lock:
            jobs[job_id]["status"] = "running"
        try:
            report = run_scan(target, settings, only=only, passive_only=passive_only, progress=progress)
            rpt.write_report(report, settings.output.formats)
            with lock:
                jobs[job_id].update(status="done", scan_id=report.scan_id, findings=report.finding_count,
                                    severity=report.severity_counts())
        except (AnonymityError, ValueError) as exc:
            with lock:
                jobs[job_id].update(status="error", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            with lock:
                jobs[job_id].update(status="error", error=f"{type(exc).__name__}: {exc}")

    # -- pages --------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        settings = cfg.load_settings()
        mods = [{"name": n, "phase": c.phase, "active": c.active, "needs": c.requires_key or c.external_tool or "",
                 "description": c.description, "enabled": settings.module_enabled(n)}
                for n, c in sorted(registry.all_modules().items(), key=lambda kv: (kv[1].phase, kv[0]))]
        return templates.TemplateResponse(request, "index.html", {
            "modules": mods, "reports": rpt.list_reports(25), "mode": settings.proxy.mode,
            "scope_empty": scope_empty(settings.scope)})

    @app.post("/scan")
    def start_scan(target: str = Form(...), module: Optional[List[str]] = Form(None), passive_only: Optional[str] = Form(None)):
        from ..core.engine import normalize_target
        try:
            target, _ = normalize_target(target)
        except ValueError as exc:
            return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
        with lock:
            seq[0] += 1
            job_id = f"job{seq[0]}"
            jobs[job_id] = {"id": job_id, "target": target, "status": "queued", "modules": {}, "started": time.time()}
        threading.Thread(target=run_job, args=(job_id, target, [m for m in (module or []) if m] or None, bool(passive_only)),
                         daemon=True).start()
        return RedirectResponse(url="/", status_code=303)

    @app.get("/api/jobs")
    def api_jobs():
        with lock:
            return JSONResponse(sorted(jobs.values(), key=lambda j: -j["started"]))

    @app.get("/api/egress")
    def api_egress():
        try:
            st = check_egress(cfg.load_settings())
        except AnonymityError as exc:
            return JSONResponse({"ok": False, "detail": str(exc)})
        return JSONResponse({"mode": st.mode, "egress_ip": st.egress_ip, "is_tor": st.is_tor, "ok": st.ok, "detail": st.detail})

    @app.get("/report/{scan_id}", response_class=HTMLResponse)
    def view_report(scan_id: str):
        try:
            return HTMLResponse(rpt.render_html(rpt.load_report(scan_id)))
        except (FileNotFoundError, ValueError):
            return HTMLResponse("<h1>Report not found</h1>", status_code=404)

    @app.get("/report/{scan_id}.{fmt}")
    def export_report(scan_id: str, fmt: str):
        if fmt not in rpt.RENDERERS:
            return PlainTextResponse("unknown format", status_code=404)
        try:
            text = rpt.RENDERERS[fmt](rpt.load_report(scan_id))
        except (FileNotFoundError, ValueError):
            return PlainTextResponse("not found", status_code=404)
        media = {"json": "application/json", "csv": "text/csv", "md": "text/markdown", "html": "text/html"}[fmt]
        return PlainTextResponse(text, media_type=media)

    # -- settings -------------------------------------------------------------------
    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, msg: str = ""):
        s = cfg.load_settings(reload=True)
        return templates.TemplateResponse(request, "settings.html", {
            "keys": keystore.status(), "scope": s.scope, "proxy": s.proxy, "tor": s.tor, "msg": msg})

    def back(msg: str) -> RedirectResponse:
        return RedirectResponse(url=f"/settings?msg={quote(msg)}", status_code=303)

    @app.post("/settings/keys")
    def save_key(service: str = Form(...), value: str = Form(""), action: str = Form("save")):
        try:
            if action == "remove":
                keystore.unset_key(service)
                return back(f"Removed {service} key.")
            keystore.set_key(service, value)
            return back(f"Saved {service} key.")
        except ValueError as exc:
            return back(str(exc))

    @app.post("/settings/scope")
    def save_scope(domains: str = Form(""), cidrs: str = Form(""), require_allowlist: Optional[str] = Form(None)):
        split = lambda t: [x.strip().lower() for x in t.replace(",", "\n").splitlines() if x.strip()]  # noqa: E731
        try:
            cfg.update_local_config("scope.allowed_domains", split(domains))
            cfg.update_local_config("scope.allowed_cidrs", [c for c in split(cidrs)])
            cfg.update_local_config("scope.require_allowlist", bool(require_allowlist))
        except ValueError as exc:
            return back(str(exc))
        return back("Scope saved.")

    @app.post("/settings/network")
    def save_network(mode: str = Form(...), proxy_url: str = Form("")):
        try:
            cfg.update_local_config("proxy.mode", mode)
            cfg.update_local_config("proxy.url", proxy_url.strip())
        except ValueError as exc:
            return back(str(exc))
        return back(f"Network mode set to {mode}.")

    return app


app = create_app()
