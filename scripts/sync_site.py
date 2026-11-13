"""Copy the site from docs/ (what GitHub Pages serves) into the package, so the gateway can serve the same files.
Run after changing anything in docs/index.html or docs/assets/. A test fails if the two copies differ."""
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent.parent
src, dst = root / "docs", root / "mcpgate" / "data" / "site"
SKIP = {"og.png"}          # only used by link previews, which fetch it from the Pages address

if dst.exists():
    shutil.rmtree(dst)
for f in [src / "index.html", *sorted((src / "assets").rglob("*"))]:
    if f.is_file() and f.name not in SKIP:
        out = dst / f.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out)
print("synced", sum(1 for _ in dst.rglob("*") if _.is_file()), "files to", dst)
