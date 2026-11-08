"""The command line side of OAuth: serve flags and the oauth command."""
import asyncio

import httpx

from mcpgate import cli
from tests.test_oauth import full_login, running


async def test_cli_revoke_all_signs_out_a_running_gateway(tmp_path, capsys):
    state = tmp_path / "oauth.json"
    async with running(tmp_path, state=state) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid, tok, *_ = await full_login(h, base)
            assert await oa.load_access_token(tok["access_token"]) is not None
            assert cli.main(["oauth", "status", "--state-file", str(state)]) == 0
            assert "1 signed-in session" in capsys.readouterr().out
            await asyncio.get_running_loop().run_in_executor(None, cli.main, ["oauth", "revoke-all", "--state-file", str(state)])
            assert await oa.load_access_token(tok["access_token"]) is None
            assert (await h.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {tok['access_token']}"})).status_code == 401


def test_cli_checks_for_serve_with_oauth(monkeypatch, capsys):
    monkeypatch.delenv("MCPGATE_PASSPHRASE", raising=False)
    assert cli.main(["serve", "--public-url", "https://x.example"]) == 2
    assert "--public-url only makes sense with --http" in capsys.readouterr().err
    assert cli.main(["serve", "--http", "--public-url", "http://example.com"]) == 2
    assert "https://" in capsys.readouterr().err
    assert cli.main(["serve", "--http", "--public-url", "https://x.example/path"]) == 2
    assert "without a path" in capsys.readouterr().err
    assert cli.main(["serve", "--http", "--public-url", "https://x.example"]) == 2
    assert "MCPGATE_PASSPHRASE" in capsys.readouterr().err
