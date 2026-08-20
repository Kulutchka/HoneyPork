"""FastAPI dashboard: auth, service toggles, Telegram config, event views."""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import auth

_BASE = Path(__file__).parent


def create_app(settings, db, event_bus, notifier, service_manager) -> FastAPI:
    app = FastAPI(title="HoneyPork", docs_url=None, redoc_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        max_age=86400,
        same_site="lax",
        https_only=False,
    )
    templates = Jinja2Templates(directory=str(_BASE / "templates"))
    app.mount("/static", StaticFiles(directory=str(_BASE / "static")), name="static")

    def get_current_user(request: Request) -> str | None:
        return request.session.get("user")

    async def require_user(request: Request) -> str:
        user = get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="not authenticated")
        return user

    # ------------------------------------------------------------- auth pages
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if get_current_user(request):
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        stored_user = (await db.get_setting("admin_username")) or settings.admin_username
        stored_hash = await db.get_setting("admin_password_hash")
        if stored_hash and auth.verify_password(password, stored_hash) and username == stored_user:
            request.session["user"] = username
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password"},
            status_code=400,
        )

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=302)

    # ------------------------------------------------------------ dashboard
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        user = get_current_user(request)
        if not user:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(request, "index.html", {"user": user})

    # ------------------------------------------------------------------- API
    @app.get("/api/stats")
    async def api_stats(user: str = Depends(require_user)):
        stats = await db.get_stats()
        stats["services"] = service_manager.status()
        stats["telegram_configured"] = notifier.enabled
        return stats

    @app.get("/api/events")
    async def api_events(limit: int = 200, user: str = Depends(require_user)):
        return {"events": await db.list_events(limit=min(limit, 1000))}

    @app.get("/api/credentials")
    async def api_credentials(limit: int = 200, user: str = Depends(require_user)):
        return {"credentials": await db.list_credentials(limit=min(limit, 1000))}

    @app.get("/api/alerts")
    async def api_alerts(limit: int = 200, unacked: bool = False, user: str = Depends(require_user)):
        return {"alerts": await db.list_alerts(limit=min(limit, 1000), unacked_only=unacked)}

    @app.post("/api/alerts/{alert_id}/ack")
    async def api_ack(alert_id: int, user: str = Depends(require_user)):
        await db.ack_alert(alert_id)
        return {"ok": True}

    @app.post("/api/services/{name}/toggle")
    async def api_toggle(name: str, request: Request, user: str = Depends(require_user)):
        if name not in service_manager.services:
            raise HTTPException(status_code=404, detail="unknown service")
        body = await request.json()
        enabled = bool(body.get("enabled", False))
        status = await service_manager.set_enabled(name, enabled)
        return {"ok": True, "services": status}

    @app.get("/api/settings/telegram")
    async def api_get_telegram(user: str = Depends(require_user)):
        token = (await db.get_setting("telegram_bot_token")) or settings.telegram_bot_token or ""
        chat_id = (await db.get_setting("telegram_chat_id")) or settings.telegram_chat_id or ""
        masked = ("*" * (len(token) - 8) + token[-8:]) if len(token) > 8 else token
        return {"token_masked": masked, "has_token": bool(token), "chat_id": chat_id}

    @app.post("/api/settings/telegram")
    async def api_set_telegram(request: Request, user: str = Depends(require_user)):
        body = await request.json()
        token = (body.get("token") or "").strip()
        chat_id = (body.get("chat_id") or "").strip()
        if token and "*" not in token:
            await db.set_setting("telegram_bot_token", token)
        await db.set_setting("telegram_chat_id", chat_id)

        new_token = (await db.get_setting("telegram_bot_token")) or ""
        new_chat = (await db.get_setting("telegram_chat_id")) or ""
        notifier.configure(new_token, new_chat)
        return {"ok": True, "configured": notifier.enabled}

    @app.post("/api/telegram/test")
    async def api_telegram_test(user: str = Depends(require_user)):
        ok = await notifier.send("Test alert from HoneyPork. Configuration is working.")
        return {"ok": ok}

    return app
