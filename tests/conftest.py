import sys
from pathlib import Path

import pytest

from mcpgate.config import Backend

DEMO = str(Path(__file__).parent / "fixtures" / "demo_server.py")


@pytest.fixture
def demo_cfg():
    def make(name="demo", **kw):
        return Backend(name=name, command=sys.executable, args=[DEMO], timeout=20, **kw)
    return make
