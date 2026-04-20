"""Enforce the raise-message convention on public-path code.

Invariant (epic agent-first, Sprint 0/6): every ``raise`` on a public
code path must include actionable next-step text. Concretely:

    1. The message must end with ``.`` (or ``?``).
    2. The message must contain at least ``MIN_WORDS`` whitespace-
       separated tokens so a caller can actually act on it.
    3. Raises inside private functions (single-underscore prefix, but
       NOT dunders like ``__init__``) are exempted — those are internal
       invariants, not user-facing errors.
    4. Bare ``raise`` statements (re-raise) are exempted.
    5. ``raise Exc(var)`` where ``var`` is not a string literal is
       skipped — we can't check messages the linter can't see.

Run manually:

    uv run python scripts/lint_raise_messages.py

Exits 0 if every raise in the target set passes, 1 otherwise.
"""

import ast
import sys
from pathlib import Path

MIN_WORDS = 8

TARGETS = [
    "src/zoomies/core/connection.py",
    "src/zoomies/core/configuration.py",
    "src/zoomies/h3/connection.py",
    "src/zoomies/h3/qpack.py",
    "src/zoomies/h3/huffman.py",
    "src/zoomies/crypto/quic_crypto.py",
]


def _extract_static_text(node: ast.AST) -> str | None:
    """Reconstruct the static (literal) portion of a message expression.

    Returns None if no static text can be recovered (e.g. the message
    is a bare variable reference).
    """
    match node:
        case ast.Constant(value=str() as s):
            return s
        case ast.JoinedStr(values=values):
            parts: list[str] = []
            for v in values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append(" X ")  # placeholder for interpolated value
            return "".join(parts)
        case ast.BinOp(op=ast.Add()):
            left = _extract_static_text(node.left)
            right = _extract_static_text(node.right)
            if left is None and right is None:
                return None
            return (left or "") + (right or "")
        case _:
            return None


def _is_exempt_scope(scope_stack: list[str]) -> bool:
    """Return True when the innermost enclosing function is private.

    Private = starts with ``_`` but is NOT a dunder (``__x__``). Dunders
    like ``__post_init__`` are user-visible and must follow the
    convention.
    """
    for name in reversed(scope_stack):
        if name.startswith("__") and name.endswith("__"):
            return False
        return name.startswith("_")
    return False


def _check_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``."""
    tree = ast.parse(path.read_text(), filename=str(path))
    violations: list[str] = []
    scope_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            scope_stack.append(node.name)
            self.generic_visit(node)
            scope_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            scope_stack.append(node.name)
            self.generic_visit(node)
            scope_stack.pop()

        def visit_Raise(self, node: ast.Raise) -> None:
            self.generic_visit(node)
            if _is_exempt_scope(scope_stack):
                return
            if node.exc is None:
                return  # bare re-raise
            if not isinstance(node.exc, ast.Call) or not node.exc.args:
                return  # raise Exc() with no message, or raise var
            text = _extract_static_text(node.exc.args[0])
            if text is None:
                return  # can't see the message statically
            stripped = text.strip()
            if not stripped:
                violations.append(f"{path}:{node.lineno}: raise message is empty")
                return
            if not stripped.endswith((".", "?")):
                violations.append(
                    f"{path}:{node.lineno}: raise message does not end with '.' "
                    f"or '?' — got {stripped[-40:]!r}"
                )
            word_count = len(stripped.split())
            if word_count < MIN_WORDS:
                violations.append(
                    f"{path}:{node.lineno}: raise message has {word_count} "
                    f"words (need ≥ {MIN_WORDS}) — got {stripped[:60]!r}"
                )

    Visitor().visit(tree)
    return violations


def main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    targets = argv[1:] or TARGETS
    all_violations: list[str] = []
    for rel in targets:
        path = (repo_root / rel).resolve() if not Path(rel).is_absolute() else Path(rel)
        if not path.exists():
            print(f"SKIP: {path} (not found)", file=sys.stderr)
            continue
        all_violations.extend(_check_file(path))

    if all_violations:
        print("Raise-message convention violations:\n", file=sys.stderr)
        for v in all_violations:
            print(f"  {v}", file=sys.stderr)
        print(
            f"\n{len(all_violations)} violation(s). "
            "Every raise on a public code path must end with '.' and "
            f"contain ≥ {MIN_WORDS} words describing the next step.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(targets)} file(s) scanned, no violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
