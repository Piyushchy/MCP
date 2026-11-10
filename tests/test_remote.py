import json
import socket

import httpx
import pytest

from mcpgate import remote
from mcpgate.config import ConfigError, Server, Settings
from mcpgate.remote import Restarter, address_problem, check, instructions, validate_settings, wanted

URL = "https://box.tail1234.ts.net"
PUBLIC = lambda host, port=None, type=None: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]  # noqa: E731
DOC = {"issuer": URL, "authorization_endpoint": URL + "/authorize", "token_endpoint": URL + "/token", "registration_endpoint": URL + "/register"}


# -- validation ---------------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://box.example.com", "https://box.example.com/mcp", "https://box.example.com/?x=1", "https://u:p@box.example.com",
                                 "ftp://box.example.com", "javascript:alert(1)", "box.example.com", "https://", "https://box.example.com/#frag"])
def test_bad_public_addresses_refused(url):
    with pytest.raises(ConfigError):
        validate_settings({"public_url": url}, 8767)


def test_good_settings_are_cleaned():
    out = validate_settings({"public_url": "https://box.example.com:8443/", "port": 9000, "allow_hosts": ["Box.Example.com", "box.example.com", "x.y"],
                             "oauth_enabled": True}, 8767)
    assert out == {"public_url": "https://box.example.com:8443", "port": 9000, "allow_hosts": ["box.example.com", "x.y"], "oauth_enabled": True}
    assert validate_settings({"public_url": ""}, 8767) == {"public_url": ""}          # clearing it is allowed


@pytest.mark.parametrize("d", [{"port": 80}, {"port": 70000}, {"port": "9000"}, {"port": True}, {"port": 8767}, {"allow_hosts": "x"},
                               {"allow_hosts": ["https://x.com"]}, {"allow_hosts": ["a b"]}, {"allow_hosts": ["x/y"]}, {"allow_hosts": ["h"] * 21},
                               {"oauth_enabled": "yes"}, {"public_url": 5}])
def test_bad_other_settings_refused(d):
    with pytest.raises(ConfigError):
        validate_settings(d, 8767)


def test_wanted_follows_the_gateways_own_rules():
    class A:
        def __init__(self, *names):
            self.n = set(names)

        def has(self, n):
            return n in self.n
    s = Settings()
    assert wanted(s, A())["listener"] is False
    s.server = Server(public_url="https://a.example/", oauth_enabled=True)
    assert wanted(s, A())["oauth"] is False                                              # no passphrase yet
    w = wanted(s, A("oauth_passphrase"))
    assert w["oauth"] and w["listener"] and w["public_url"] == "https://a.example"
    assert wanted(s, A(), env_pass=True)["oauth"] is True
    s.server.static_token_enabled = True
    assert wanted(s, A("static_token"))["static"] is True and wanted(s, A(), env_token=True)["static"] is True


def test_supervised_and_restarter(monkeypatch):
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    monkeypatch.delenv("MCPGATE_SUPERVISED", raising=False)
    assert remote.supervised() is False
    monkeypatch.setenv("INVOCATION_ID", "abc")
    assert remote.supervised() is True
    r, stopped = Restarter(), []
    r.attach(lambda: stopped.append(1))
    assert not r.requested
    r.trigger()
    assert r.requested and stopped == [1] and Restarter.EXIT_CODE == 75


# -- the address guard ----------------------------------------------------------------------------
def resolver(*ips):
    return lambda host, port=None, type=None: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.10", "172.16.5.5", "169.254.169.254", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1"])
def test_private_and_local_addresses_are_refused(ip):
    assert "private or local" in address_problem("box.example.com", resolver(ip))


def test_public_and_tailnet_addresses_are_allowed():
    for ip in ["93.184.216.34", "8.8.8.8", "100.101.102.103", "fd7a:115c:a1e0::1", "2606:4700::1111"]:
        assert address_problem("box.tail1.ts.net", resolver(ip)) is None, ip


def test_one_private_answer_among_public_ones_is_refused():
    assert address_problem("x.example.com", resolver("93.184.216.34", "10.0.0.1"))


def test_ip_literals_and_unresolvable_names():
    for host in ["127.0.0.1", "93.184.216.34", "[::1]", "::1"]:
        assert "host name" in address_problem(host)
    def boom(*a, **k):
        raise socket.gaierror("no such host")
    assert address_problem("nope.example.invalid", boom) is None      # reported as unreachable by the request itself


# -- the check ----------------------------------------------------------------------------------------
class Net:
    """A fake network: records every request, so tests can prove where the check went."""

    def __init__(self, routes):
        self.routes, self.seen = routes, []

    def __call__(self, request: httpx.Request):
        self.seen.append((request.url.host, request.url.path, request.method, dict(request.headers)))
        h = self.routes.get(request.url.path)
        if isinstance(h, Exception):
            raise h
        return h(request) if callable(h) else (h or httpx.Response(404))

    def transport(self):
        return httpx.MockTransport(self)


def good():
    return Net({"/.well-known/oauth-authorization-server": httpx.Response(200, json=DOC),
                "/mcp": httpx.Response(401, headers={"www-authenticate": 'Bearer resource_metadata="x"'})})


async def run(net, url=URL):
    return {r["name"]: r for r in await check(url, transport=net.transport(), resolve=PUBLIC)}


async def test_everything_works():
    net = good()
    res = await run(net)
    assert [r["ok"] for r in res.values()] == [True, True, True]
    assert {(h, p) for h, p, _, _ in net.seen} == {("box.tail1234.ts.net", "/.well-known/oauth-authorization-server"), ("box.tail1234.ts.net", "/mcp")}
    assert all(m == "GET" for _, _, m, _ in net.seen) and all("authorization" not in hd for *_, hd in net.seen)


async def test_redirects_are_not_followed_and_never_leave_the_host():
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(302, headers={"location": "https://evil.example/steal"}),
               "/mcp": httpx.Response(301, headers={"location": "http://169.254.169.254/latest"})})
    res = await run(net)
    assert res["Discovery"]["ok"] is False and "redirect" in res["Discovery"]["detail"].lower()
    assert res["MCP endpoint"]["ok"] is False
    assert {h for h, *_ in net.seen} == {"box.tail1234.ts.net"}


async def test_private_address_makes_no_request_at_all():
    net = good()
    res = await check(URL, transport=net.transport(), resolve=resolver("192.168.1.9"))
    assert len(res) == 1 and res[0]["ok"] is False and net.seen == []


async def test_only_the_given_public_url_form_is_accepted():
    for bad in ["https://box.example.com/other/path", "http://box.example.com", "https://u:p@box.example.com", "file:///etc/passwd"]:
        with pytest.raises(ConfigError):
            await check(bad, transport=good().transport(), resolve=PUBLIC)


@pytest.mark.parametrize("status,headers,needle", [
    (404, {}, "not this gateway"), (403, {"cf-ray": "1"}, "Cloudflare"), (503, {"server": "cloudflare"}, "Cloudflare"), (500, {}, "Unexpected")])
async def test_discovery_failures_are_explained(status, headers, needle):
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(status, headers=headers), "/mcp": httpx.Response(401, headers={"www-authenticate": "Bearer"})})
    res = await run(net)
    assert res["Discovery"]["ok"] is False and needle in res["Discovery"]["detail"] and res["Discovery"]["advice"]


async def test_wrong_issuer_and_incomplete_and_not_json():
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, json={**DOC, "issuer": "https://other.example"})})
    d = (await run(net))["Discovery"]
    assert d["ok"] is False and "other.example" in d["detail"] and "exactly" in d["advice"]
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, json={"issuer": URL})})
    assert "incomplete" in (await run(net))["Discovery"]["detail"]
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, text="<html>hello</html>")})
    assert (await run(net))["Discovery"]["ok"] is False
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, content=b"x" * 500_000)})
    assert (await run(net))["Discovery"]["ok"] is False                                    # big bodies are cut, not read whole


async def test_unreachable_timeout_and_tls_are_explained():
    for exc, needle in [(httpx.ConnectError("refused"), "Could not connect"), (httpx.ConnectTimeout("slow"), "did not answer"),
                        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), "certificate")]:
        net = Net({"/.well-known/oauth-authorization-server": exc})
        res = await check(URL, transport=net.transport(), resolve=PUBLIC)
        assert res[1]["ok"] is False and needle in res[1]["detail"] and len(res) == 2


async def test_mcp_endpoint_without_login_is_flagged_as_dangerous():
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, json=DOC), "/mcp": httpx.Response(200, json={})})
    m = (await run(net))["MCP endpoint"]
    assert m["ok"] is False and "Anyone" in m["detail"]
    net = Net({"/.well-known/oauth-authorization-server": httpx.Response(200, json=DOC), "/mcp": httpx.Response(401)})
    assert (await run(net))["MCP endpoint"]["ok"] is None


# -- instructions ------------------------------------------------------------------------------------------
def test_instructions_carry_the_real_values():
    i = instructions("https://box.tail1234.ts.net", 8766)
    assert i["connector_url"] == "https://box.tail1234.ts.net/mcp" and "sudo tailscale funnel --bg 8766" in i["tailscale"]["commands"]
    assert any("--https=8443 8766" in c for c in i["tailscale"]["commands"]) and "cloudflared tunnel --url http://127.0.0.1:8766" in i["cloudflare"]["commands"]
    assert any("https://box.tail1234.ts.net/mcp" in s for s in i["claude"]) and any("captcha" in i["cloudflare"]["intro"] for _ in [0])
    second = instructions("https://box.tail1234.ts.net:8443", 9000)
    assert second["connector_url"].endswith(":8443/mcp") and second["tailscale"]["commands"] == ["sudo tailscale funnel --bg --https=8443 9000"]
    assert "<your-machine>" in instructions("", 8766)["connector_url"]


# -- OAuth store: sessions and last-used ------------------------------------------------------------------------
async def test_last_used_is_written_at_most_once_a_minute(tmp_path):
    from mcp.shared.auth import OAuthClientInformationFull

    from mcpgate.oauth import GatewayOAuth
    prov = GatewayOAuth(URL, passphrase="correct horse battery", state_path=tmp_path / "o.json")
    import time
    clock = [time.time()]
    prov._now = lambda: clock[0]
    client = OAuthClientInformationFull(client_id="c1", client_name="app", redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none")
    await prov.register_client(client)
    tok = prov._issue("c1", [], None)
    writes = []
    real = prov.store.save
    prov.store.save = lambda: (writes.append(1), real())[1]
    for dt in (1, 20, 30):
        clock[0] += dt
        await prov.load_access_token(tok.access_token)
    assert writes == []
    clock[0] += 20
    await prov.load_access_token(tok.access_token)
    assert writes == [1]
    row = prov.store.sessions()[0]
    assert row["client_name"] == "app" and row["last_used"] == int(clock[0])
    assert "token" not in " ".join(row) and tok.access_token not in str(row)
