"""Admin login: one admin, a passphrase (scrypt), a one-time setup code for the first run, server-side sessions,
CSRF tokens and step-up re-authentication for dangerous actions. Nothing here ever echoes a passphrase."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from ..authstore import MIN_PASSPHRASE, AuthStore
from ..config import ConfigError

COOKIE = "mcpgate_admin"
IDLE = 30 * 60          # sign out after 30 minutes without activity
ABSOLUTE = 8 * 3600     # and after 8 hours whatever happens
STEPUP = 5 * 60         # how long a re-entered passphrase unlocks dangerous actions
SETUP_TTL = 30 * 60     # a setup code is valid for 30 minutes and works once
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I


class AuthError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


class Limiter:
    """Three free tries, then waits of 2, 4, 8 ... seconds up to 15 minutes. Reset by a success."""

    def __init__(self, clock, free: int = 3, cap: int = 900):
        self.clock, self.free, self.cap, self.fails, self.until = clock, free, cap, 0, 0.0

    def wait(self) -> int:
        return max(0, int(self.until - self.clock() + 0.999))

    def fail(self) -> None:
        self.fails += 1
        if self.fails > self.free:
            self.until = self.clock() + min(self.cap, 2 ** (self.fails - self.free))

    def ok(self) -> None:
        self.fails, self.until = 0, 0.0


class Session:
    __slots__ = ("created", "last", "csrf", "stepup_until")

    def __init__(self, now: float):
        self.created = self.last = now
        self.csrf = secrets.token_urlsafe(32)
        self.stepup_until = 0.0


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_code(code: str) -> str:
    return "".join(c for c in str(code).upper() if c.isalnum())


class AdminAuth:
    def __init__(self, store: AuthStore, clock=time.time, audit=None):
        self.store, self.clock, self.audit = store, clock, audit or (lambda **_: None)
        self.sessions: dict[str, Session] = {}
        self.login_limit, self.setup_limit = Limiter(clock), Limiter(clock)

    # -- state -------------------------------------------------------------
    def state(self) -> str:
        return "login" if self.store.has("admin_passphrase") else "setup"

    def issue_setup_code(self) -> str:
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(20))
        self.store.set_token("admin_setup", raw, ttl=SETUP_TTL)
        return "-".join(raw[i:i + 5] for i in range(0, 20, 5))

    # -- helpers -----------------------------------------------------------
    def _guard(self, limiter: Limiter) -> None:
        w = limiter.wait()
        if w:
            raise AuthError(429, f"too many attempts, try again in {w} seconds", w)

    def _new_session(self) -> tuple[str, Session]:
        self._expire()
        cookie = secrets.token_urlsafe(32)
        self.sessions[_h(cookie)] = sess = Session(self.clock())
        return cookie, sess

    def _expire(self) -> None:
        now = self.clock()
        for k in [k for k, s in self.sessions.items() if now - s.last > IDLE or now - s.created > ABSOLUTE]:
            del self.sessions[k]

    def _passphrase_ok(self, value) -> bool:
        return isinstance(value, str) and self.store.verify("admin_passphrase", value)

    # -- first run ---------------------------------------------------------
    def setup(self, code, passphrase) -> tuple[str, Session]:
        if self.state() != "setup":
            raise AuthError(409, "the admin passphrase is already set")
        self._guard(self.setup_limit)
        if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
            raise AuthError(400, f"the passphrase must be at least {MIN_PASSPHRASE} characters")
        if not isinstance(code, str) or not self.store.verify("admin_setup", normalize_code(code)):
            self.setup_limit.fail()
            self.audit(event="admin_setup_failed")
            raise AuthError(403, "that setup code is wrong or has expired")
        self.setup_limit.ok()
        try:
            self.store.set_passphrase("admin_passphrase", passphrase)
        except ConfigError as e:
            raise AuthError(400, str(e)) from None
        self.store.clear("admin_setup")            # single use
        self.sessions.clear()
        self.audit(event="admin_setup")
        return self._new_session()

    # -- login / session -----------------------------------------------------
    def login(self, passphrase) -> tuple[str, Session]:
        if self.state() != "login":
            raise AuthError(409, "finish the first-run setup first")
        self._guard(self.login_limit)
        if not self._passphrase_ok(passphrase):
            self.login_limit.fail()
            self.audit(event="admin_login_failed")
            raise AuthError(401, "wrong passphrase")
        self.login_limit.ok()
        self.audit(event="admin_login")
        return self._new_session()                  # always a fresh session id

    def get(self, cookie: str | None) -> Session | None:
        if not cookie:
            return None
        self._expire()
        sess = self.sessions.get(_h(cookie))
        if sess is None:
            return None
        if self.state() != "login":                  # passphrase cleared from the shell: drop everyone
            self.sessions.clear()
            return None
        sess.last = self.clock()
        return sess

    def logout(self, cookie: str | None) -> None:
        if cookie:
            self.sessions.pop(_h(cookie), None)
        self.audit(event="admin_logout")

    @staticmethod
    def csrf_ok(sess: Session, token: str) -> bool:
        return bool(token) and hmac.compare_digest(sess.csrf, token)

    # -- step-up -------------------------------------------------------------
    def stepup(self, sess: Session, passphrase) -> None:
        self._guard(self.login_limit)
        if not self._passphrase_ok(passphrase):
            self.login_limit.fail()
            self.audit(event="admin_stepup_failed")
            raise AuthError(401, "wrong passphrase")
        self.login_limit.ok()
        sess.stepup_until = self.clock() + STEPUP
        self.audit(event="admin_stepup")

    def stepup_ok(self, sess: Session) -> bool:
        return self.clock() < sess.stepup_until

    # -- changing the passphrase --------------------------------------------
    def change_passphrase(self, sess: Session, current, new) -> tuple[str, Session]:
        self._guard(self.login_limit)
        if not self._passphrase_ok(current):
            self.login_limit.fail()
            raise AuthError(401, "wrong passphrase")
        self.login_limit.ok()
        if not isinstance(new, str) or len(new) < MIN_PASSPHRASE:
            raise AuthError(400, f"the new passphrase must be at least {MIN_PASSPHRASE} characters")
        self.store.set_passphrase("admin_passphrase", new)
        self.sessions.clear()                       # every other session is signed out
        self.audit(event="admin_passphrase_changed")
        return self._new_session()
