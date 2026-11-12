"""Every import in the lab's code resolves, including imports inside functions (which other tests may never run)."""

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Run on the hosts' system Python or only inside Docker: not installed in the lab's venv.
ALLOWED_MISSING = {"sensor"}


def _imported_modules(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_every_import_in_vendors_and_assets_resolves():
    missing = {}
    for path in [*ROOT.joinpath("vendors").rglob("*.py"), *ROOT.joinpath("assets").rglob("*.py")]:
        for name in _imported_modules(path) - ALLOWED_MISSING:
            if importlib.util.find_spec(name) is None:
                missing.setdefault(name, []).append(str(path.relative_to(ROOT)))
    assert missing == {}
