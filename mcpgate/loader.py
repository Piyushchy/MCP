"""Loading the complete settings: the config file plus drop-in custom servers."""
from __future__ import annotations

from pathlib import Path

from . import config as cfgmod
from . import custom
from .config import Settings


def load_settings(path: Path | str | None = None) -> Settings:
    return custom.with_custom(cfgmod.load(path))


def _stat(p: Path):
    try:
        st = p.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def signature(path: Path | str | None, extra: list[Path] | None = None) -> tuple:
    """A cheap fingerprint of everything that feeds the settings: the config file, the custom folder and any
    extra files (secrets). It changes when any of them is added, removed or edited."""
    p = Path(path).expanduser() if path else cfgmod.config_path()
    folder = None
    try:
        folder = custom.folder(cfgmod.load(p))
    except Exception:  # noqa: BLE001 - a broken file still gets watched, via its own fingerprint
        folder = custom.default_dir()
    drop_ins = tuple(sorted((f.name, _stat(f)) for f in folder.glob("*.py"))) if folder.is_dir() else ()
    return (_stat(p), drop_ins, tuple(_stat(Path(x)) for x in (extra or [])))
