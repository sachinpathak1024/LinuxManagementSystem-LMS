"""Sentinel API entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__, collectors
from .config import settings
from .core.security import hash_password
from .database import Base, SessionLocal, engine
from .models import User
from .routers import alerts, auth, firewall, logs, security, services, system
from .websocket import ws_endpoint

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel")

scheduler = AsyncIOScheduler()


def init_db_and_seed() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == settings.admin_username).first():
            db.add(
                User(
                    username=settings.admin_username,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                )
            )
            db.commit()
            log.info("Seeded initial admin user '%s'", settings.admin_username)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    init_db_and_seed()
    collectors.set_loop(asyncio.get_running_loop())
    scheduler.add_job(collectors.sample_metrics, "interval",
                      seconds=settings.sample_interval_seconds, id="metrics", max_instances=1)
    scheduler.add_job(collectors.ingest_events, "interval",
                      seconds=settings.scan_interval_seconds, id="events", max_instances=1)
    scheduler.add_job(collectors.prune_old_data, "interval", hours=6, id="prune")
    scheduler.start()
    log.info("Sentinel %s started (host commands: %s)", __version__,
             "ENABLED" if settings.allow_host_commands else "disabled")
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Sentinel",
    version=__version__,
    description="Local environment management & security dashboard",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__,
            "host_commands": settings.allow_host_commands}

@app.get("/api/health/liveness")
def health():
    return {"status": "ok", "version": __version__,
            "host_commands": settings.allow_host_commands}

@app.get("/api/health/readiness")
def health():
    return {"status": "ok", "version": __version__,
            "host_commands": settings.allow_host_commands}


app.include_router(auth.router)
app.include_router(system.router)
app.include_router(firewall.router)
app.include_router(security.router)
app.include_router(logs.router)
app.include_router(services.router)
app.include_router(alerts.router)


@app.websocket("/api/ws")
async def websocket_route(ws: WebSocket):
    await ws_endpoint(ws)
