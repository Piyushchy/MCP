"""Run the real service in a subprocess: the admin UI is on loopback, and the public listener has no admin code."""
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(tmp_path, *extra, env=None, admin_port=None, port=None):
    admin_port = admin_port or free_port()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f"[server]\nadmin_port = {admin_port}\nport = {port or free_port()}\n")
    cfg.chmod(0o600)
    e = {**os.environ, "MCPGATE_CONFIG": str(cfg), "XDG_STATE_HOME": str(tmp_path / "state"), **(env or {})}
    proc = subprocess.Popen([sys.executable, "-m", "mcpgate", "serve", "--service", *extra], env=e,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    return proc, admin_port


def wait_for(url, proc, headers=None):
    for _ in range(100):
        if proc.poll() is not None:
            raise AssertionError(f"service exited early: {proc.stderr.read()}")
        try:
            return httpx.get(url, headers=headers, timeout=2)
        except httpx.TransportError:
            time.sleep(0.1)
    raise AssertionError("service did not start")


def stop(proc):
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_service_without_remote_access_runs_only_the_admin_ui(tmp_path):
    proc, admin = start(tmp_path)
    try:
        r = wait_for(f"http://127.0.0.1:{admin}/api/health", proc)
        assert r.status_code == 200
        cfg_port = int((tmp_path / "config.toml").read_text().split("port = ")[-1])
        with socket.socket() as s:   # no public listener exists
            assert s.connect_ex(("127.0.0.1", cfg_port)) != 0
    finally:
        stop(proc)


def test_admin_not_reachable_on_other_interfaces(tmp_path):
    proc, admin = start(tmp_path)
    try:
        wait_for(f"http://127.0.0.1:{admin}/api/health", proc)
        addrs = {a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)} - {"127.0.0.1", "127.0.1.1"}
        for ip in addrs:
            with socket.socket() as s:
                s.settimeout(1)
                assert s.connect_ex((ip, admin)) != 0, f"admin UI answered on {ip}"
    finally:
        stop(proc)


def test_public_listener_has_no_admin_paths(tmp_path):
    port = free_port()
    proc, admin = start(tmp_path, env={"MCPGATE_TOKEN": "t" * 32}, port=port)
    try:
        wait_for(f"http://127.0.0.1:{admin}/api/health", proc)
        base = f"http://127.0.0.1:{port}"
        auth = {"authorization": "Bearer " + "t" * 32}
        home = httpx.get(base + "/", timeout=3)           # the project site is served here; it is not the admin page
        assert home.status_code == 200 and "One connection to every MCP server" in home.text and "mcpgate admin" not in home.text
        assert httpx.post(base + "/", headers=auth, timeout=3).status_code in (401, 404, 405)
        for path in ["/static/app.js", "/static/app.css", "/api/health", "/api/login", "/api/backends", "/admin", "/ui"]:
            for headers in ({}, auth):   # with and without credentials
                r = httpx.get(base + path, headers=headers, timeout=3)
                assert r.status_code in (401, 404), (path, r.status_code)
                assert "mcpgate admin" not in r.text
            assert httpx.post(base + path, headers=auth, timeout=3).status_code in (401, 404, 405)
    finally:
        stop(proc)


def test_admin_port_in_use_means_no_start_and_no_fallback(tmp_path):
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    try:
        proc, _ = start(tmp_path, admin_port=busy.getsockname()[1])
        assert proc.wait(15) != 0
        assert "will not start elsewhere" in proc.stderr.read()
    finally:
        busy.close()
