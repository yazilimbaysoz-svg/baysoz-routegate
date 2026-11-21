# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

from routegate import matches, paths
from routegate.model import HeaderMatch, MatchValue, PathMatch, RouteMatch


def test_path_intersection_and_coverage():
    exact = PathMatch("Exact", "/api/health")
    prefix = PathMatch("PathPrefix", "/api")
    other = PathMatch("Exact", "/other")
    assert paths.intersects(exact, prefix).empty is False
    assert paths.intersects(exact, other).empty is True
    assert paths.covers(prefix, exact) == (True, True)
    assert paths.covers(exact, prefix) == (False, True)
    assert paths.specificity(exact) < paths.specificity(prefix)


def test_regex_paths_are_conservative():
    regex = PathMatch("RegularExpression", "^/api/.+$")
    prefix = PathMatch("PathPrefix", "/api")
    result = paths.intersects(regex, prefix)
    assert result.empty is False
    assert result.certain is False
    assert paths.covers(prefix, regex) == (False, True)


def _match(path: PathMatch, headers=(), query=(), method=None) -> RouteMatch:
    return RouteMatch(path, tuple(headers), tuple(query), method)


def test_header_ors_and_ands():
    left = _match(PathMatch("Exact", "/"), [HeaderMatch("x-tier", (MatchValue("Exact", "gold"),))])
    right = _match(
        PathMatch("Exact", "/"), [HeaderMatch("x-tier", (MatchValue("Exact", "silver"),))]
    )
    assert matches.route_intersects(left, right)[0] is False
    union = _match(
        PathMatch("Exact", "/"),
        [HeaderMatch("x-tier", (MatchValue("Exact", "gold"), MatchValue("Exact", "silver")))],
    )
    assert matches.route_intersects(union, right)[0] is True
    assert matches.route_covers(union, right)[0] is True


def test_method_and_query_constraints():
    get = _match(PathMatch("Exact", "/"), method="GET")
    post = _match(PathMatch("Exact", "/"), method="POST")
    any_method = _match(PathMatch("Exact", "/"))
    assert matches.route_intersects(get, post)[0] is False
    assert matches.route_intersects(get, any_method) == (True, True)
    assert matches.route_covers(any_method, get)[0] is True
    assert matches.route_covers(get, any_method)[0] is False
    with_query = _match(
        PathMatch("Exact", "/"), query=[HeaderMatch("debug", (MatchValue("Present", None),))]
    )
    assert matches.route_intersects(any_method, with_query) == (True, True)
    assert matches.route_covers(any_method, with_query)[0] is True
    assert matches.route_covers(with_query, any_method)[0] is False


def test_regex_value_certainty():
    regex = MatchValue("RegularExpression", "^v[0-9]+$")
    exact = MatchValue("Exact", "v42")
    assert matches.value_intersects(regex, exact)[1] is True
    assert matches.value_intersects(regex, MatchValue("Prefix", "/x"))[1] is False
