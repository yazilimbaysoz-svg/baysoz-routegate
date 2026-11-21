# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import pytest

from routegate import hostnames


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("shop.example.com", "shop.example.com", True),
        ("shop.example.com", "*.example.com", True),
        ("deep.shop.example.com", "*.example.com", False),
        ("example.com", "*.example.com", False),
        ("*.example.com", "*.example.com", True),
        ("*.example.com", "*.shop.example.com", False),
        ("*", "anything.test", True),
        ("SHOP.EXAMPLE.COM.", "shop.example.com", True),
    ],
)
def test_hostname_intersection(first, second, expected):
    assert hostnames.intersects(hostnames.normalize(first), hostnames.normalize(second)) is expected


@pytest.mark.parametrize(
    ("broader", "narrower", "expected"),
    [
        ("*", "shop.example.com", True),
        ("*.example.com", "shop.example.com", True),
        ("*.example.com", "deep.shop.example.com", False),
        ("shop.example.com", "*.example.com", False),
        ("*.example.com", "*.example.com", True),
    ],
)
def test_hostname_containment(broader, narrower, expected):
    assert hostnames.covers(broader, narrower) is expected


def test_hostname_specificity_and_validation():
    assert hostnames.specificity("shop.example.com") < hostnames.specificity("*.example.com")
    assert hostnames.specificity("a.b.example.com") < hostnames.specificity("*.example.com")
    assert hostnames.is_valid("bad..example.com") is False
    assert hostnames.is_valid("*.example.com") is True
