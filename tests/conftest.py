# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def demo_path() -> str:
    return str(FIXTURES / "demo.yaml")


def write_manifest(tmp_path: Path, text: str, name: str = "manifests.yaml") -> str:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return str(target)
