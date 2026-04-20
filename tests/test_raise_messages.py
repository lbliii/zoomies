"""Regression test: public-path raises must follow the message convention.

Runs the same check as ``scripts/lint_raise_messages.py`` so the rule
is enforced locally under ``pytest`` as well as in CI.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "lint_raise_messages.py"


def test_public_raises_follow_convention() -> None:
    """Every raise in public-path files ends with '.' and has ≥ 8 words."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Raise-message convention violated:\n{result.stderr}\n{result.stdout}"
    )


def test_linter_fires_on_bad_raise(tmp_path: Path) -> None:
    """The linter actually rejects a short/period-less raise."""
    bad = tmp_path / "bad.py"
    bad.write_text("def public_func() -> None:\n    raise ValueError('nope')\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(bad)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, "linter must reject a too-short raise"
    assert "nope" in result.stderr


def test_linter_exempts_private_functions(tmp_path: Path) -> None:
    """Raises inside single-underscore-prefixed functions are skipped."""
    good = tmp_path / "private.py"
    good.write_text("def _internal() -> None:\n    raise ValueError('bad')\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(good)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"linter should exempt private functions:\n{result.stderr}"


def test_linter_enforces_dunder_methods(tmp_path: Path) -> None:
    """Dunder methods (``__post_init__`` etc.) are user-facing — enforced."""
    bad = tmp_path / "dunder.py"
    bad.write_text(
        "class Cfg:\n    def __post_init__(self) -> None:\n        raise ValueError('no')\n"
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(bad)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, "linter must enforce on dunder methods"


@pytest.mark.parametrize(
    "src",
    [
        # bare re-raise is exempt
        "def f():\n    try:\n        pass\n    except Exception:\n        raise\n",
        # variable message (can't be statically checked) — skipped
        "def f(msg):\n    raise ValueError(msg)\n",
    ],
)
def test_linter_skips_unverifiable_raises(tmp_path: Path, src: str) -> None:
    """Bare re-raises and variable-message raises are not flagged."""
    p = tmp_path / "skip.py"
    p.write_text(src)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(p)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"should skip unverifiable raises:\n{result.stderr}"
