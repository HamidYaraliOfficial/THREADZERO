"""Bridge to the Haskell core: project loading (imports), analysis, formatting, refactoring."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*;', re.M)


class CoreError(RuntimeError):
    """The Haskell core is missing or failed."""


def find_core() -> str:
    env = os.environ.get("THREADZERO_CORE")
    if env and Path(env).exists():
        return env
    exe = "threadzero-core.exe" if os.name == "nt" else "threadzero-core"
    for cand in (ROOT / "haskell" / "build" / exe, ROOT / "bin" / exe, Path(sys.prefix) / "bin" / exe):
        if cand.exists():
            return str(cand)
    found = shutil.which("threadzero-core")
    if found:
        return found
    raise CoreError(
        "threadzero-core (the Haskell core) was not found. Build it with `make core` "
        "(requires GHC >= 9.4) or set THREADZERO_CORE=/path/to/threadzero-core."
    )


def run_core(args: list[str], stdin: str | None = None, timeout: int = 120) -> str:
    proc = subprocess.run(
        [find_core(), *args], input=stdin.encode("utf-8") if stdin is not None else None,
        capture_output=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise CoreError(proc.stderr.decode("utf-8", "replace").strip() or f"core exited with {proc.returncode}")
    return proc.stdout.decode("utf-8")


_version_cache: str | None = None


def core_version() -> str:
    global _version_cache
    if _version_cache is None:
        _version_cache = run_core(["--version"]).strip()
    return _version_cache


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Bundle:
    """A project flattened into one text with '#@file' pragmas for exact source mapping."""
    text: str
    files: dict[str, str] = field(default_factory=dict)  # display path -> content
    root: str = ""

    @property
    def hash(self) -> str:
        return sha256_hex(canonical_json(self.files))


def _display(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_project(path: str | Path) -> Bundle:
    """Resolve `import "x.tz";` recursively (dependencies first, each file once)."""
    p = Path(path)
    if p.is_dir():
        cand = sorted(p.glob("*.tz"))
        p = p / "main.tz" if (p / "main.tz").exists() or len(cand) != 1 else cand[0]
    if not p.exists():
        raise FileNotFoundError(f"project file not found: {p}")
    base = p.resolve().parent
    order: list[Path] = []
    seen: set[Path] = set()
    stack: list[Path] = []

    def visit(f: Path) -> None:
        f = f.resolve()
        if f in stack:
            raise CoreError("circular import: " + " -> ".join(_display(x, base) for x in stack + [f]))
        if f in seen:
            return
        stack.append(f)
        text = f.read_text(encoding="utf-8")
        for rel in IMPORT_RE.findall(text):
            dep = (f.parent / rel).resolve()
            if not dep.exists():
                raise CoreError(f"{_display(f, base)}: import not found: {rel}")
            visit(dep)
        stack.pop()
        seen.add(f)
        order.append(f)

    visit(p)
    files = {_display(f, base): f.read_text(encoding="utf-8") for f in order}
    return Bundle(bundle_text(files), files, str(base))


def bundle_text(files: dict[str, str]) -> str:
    return "".join(f"#@file {name}\n{content.rstrip()}\n" for name, content in files.items())


def bundle_from_source(source: str, name: str = "main.tz") -> Bundle:
    return Bundle(bundle_text({name: source}), {name: source}, "")


def analyze_bundle(b: Bundle) -> dict:
    out = json.loads(run_core(["analyze", "-"], stdin=b.text))
    out["sourceHash"] = b.hash
    out["files"] = sorted(b.files)
    return out


def analyze(source: str | Path | Bundle, name: str = "main.tz") -> dict:
    """Analyze a path, a Bundle, or raw DSL text (a string containing a newline or a keyword)."""
    if isinstance(source, Bundle):
        return analyze_bundle(source)
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).exists()):
        return analyze_bundle(load_project(source))
    return analyze_bundle(bundle_from_source(str(source), name))


def parse(text: str) -> dict:
    return json.loads(run_core(["parse", "-"], stdin=bundle_text({"main.tz": text})))


def fmt(text: str) -> str:
    return run_core(["fmt", "-"], stdin=bundle_text({"main.tz": text}))


def refactor(source: str | Path | Bundle, finding_id: str) -> dict:
    b = source if isinstance(source, Bundle) else (
        load_project(source) if isinstance(source, Path) else bundle_from_source(source))
    return json.loads(run_core(["refactor", "-", finding_id], stdin=b.text))


def smt(source: str | Path | Bundle, rule_id: str) -> str:
    b = source if isinstance(source, Bundle) else (
        load_project(source) if isinstance(source, Path) else bundle_from_source(source))
    return run_core(["smt", "-", rule_id], stdin=b.text)


def solve_with_z3(smt_text: str) -> str | None:
    """Optional external solver adapter: uses z3 (binary or python module) when present."""
    z3 = shutil.which("z3")
    if z3:
        r = subprocess.run([z3, "-in", "-smt2"], input=smt_text.encode(), capture_output=True, timeout=30)
        return r.stdout.decode()
    try:
        import z3 as z3mod  # type: ignore
        s = z3mod.Solver()
        s.from_string(smt_text)
        return str(s.check())
    except Exception:
        return None
