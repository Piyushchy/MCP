"""Shared setup for the admin API tests: a real hub with the demo backend, behind the real admin app."""
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import httpx

from mcpgate import config as cfgmod
from mcpgate import loader
from mcpgate.admin import app as admin
from mcpgate.admin.context import AdminContext
from mcpgate.admin.session import AdminAuth
from mcpgate.authstore import AuthStore
from mcpgate.config import Backend, Settings
from mcpgate.hub import Hub
from mcpgate.reload import Reloader
from mcpgate.secretstore import SecretStore

DEMO = str(Path(__file__).parent / "fixtures" / "demo_server.py")
PORT = 8767
HOST = f"127.0.0.1:{PORT}"
PASS = "correct horse battery"


def demo(name="demo", **kw):
    return Backend(name=name, transport="stdio", command=sys.executable, args=[DEMO], **kw)


class Rig:
    def __init__(self, c, ctx, auth, csrf, tmp):
        self.c, self.ctx, self.auth, self.csrf, self.tmp = c, ctx, auth, csrf, tmp
        self.hub, self.secrets, self.path = ctx.hub, ctx.secrets, ctx.config_file

    def headers(self, csrf=True, **extra):
        h = {"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json", **extra}
        if csrf:
            h["x-csrf-token"] = self.csrf
        return h

    async def get(self, path):
        return await self.c.get(path, headers={"host": HOST})

    async def post(self, path, data=None, csrf=True):
        return await self.c.post(path, headers=self.headers(csrf), content=json.dumps(data if data is not None else {}))

    async def stepup(self):
        r = await self.post("/api/stepup", {"passphrase": PASS})
        assert r.status_code == 200

    def audit_text(self):
        p = self.tmp / "audit.jsonl"
        return p.read_text() if p.exists() else ""

    def file_text(self):
        return self.path.read_text()


@asynccontextmanager
async def rig(tmp_path, backends=None, secrets=None, custom=False):
    path = tmp_path / "config.toml"
    settings = Settings(audit_log=str(tmp_path / "audit.jsonl"), backends=backends if backends is not None else {"demo": demo()})
    settings.server.allow_custom_commands = custom
    cfgmod.save(settings, path)
    store = SecretStore(tmp_path / "secrets.json")
    for k, v in (secrets or {}).items():
        store.set(k, v)
    hub = Hub(loader.load_settings(path), secrets=store)
    reloader = Reloader(hub, path)
    auth = AdminAuth(AuthStore(tmp_path / "auth.json"), audit=lambda **f: hub.audit.log(**f))
    ctx = AdminContext(hub, path, reloader, store, auth)
    app = admin.make_app(PORT, auth=auth, ctx=ctx)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"http://{HOST}") as c:
        h = {"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"}
        r = await c.post("/api/setup", headers=h, content=json.dumps({"code": auth.issue_setup_code(), "passphrase": PASS}))
        assert r.status_code == 200, r.text
        try:
            yield Rig(c, ctx, auth, r.json()["csrf"], tmp_path)
        finally:
            await hub.stop()
