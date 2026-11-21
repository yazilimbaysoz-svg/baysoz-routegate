# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import hostnames
from .model import (
    BackendRef,
    Gateway,
    HeaderMatch,
    HttpRoute,
    KindConstraint,
    Listener,
    MatchValue,
    Namespace,
    ParentRef,
    PathMatch,
    RouteMatch,
    Rule,
    SelectorExpression,
)

GROUP = "gateway.networking.k8s.io"
VERSION = "v1"
MATCH_TYPES = {"Exact", "Prefix", "RegularExpression", "Present"}
PATH_TYPES = {"Exact", "PathPrefix", "RegularExpression"}
OPERATORS = {"In", "NotIn", "Exists", "DoesNotExist"}


class ManifestError(Exception):
    pass


@dataclass(frozen=True)
class ManifestSet:
    gateways: tuple[Gateway, ...]
    routes: tuple[HttpRoute, ...]
    namespaces: tuple[Namespace, ...]
    stats: dict[str, int]


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{label}: expected a mapping")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ManifestError(f"{label}: expected a sequence")
    return value


def _text(value: Any, label: str, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ManifestError(f"{label}: expected a string")
    return value.strip()


def _port(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise ManifestError(f"{label}: expected a port in 1..65535")
    return value


def _regex(value: str, label: str) -> None:
    try:
        re.compile(value)
    except re.error as exc:
        raise ManifestError(f"{label}: invalid regular expression: {exc}") from exc


def _value_matches(raw: Any, label: str) -> tuple[MatchValue, ...]:
    if raw is None:
        return (MatchValue("Present", None),)
    if isinstance(raw, str):
        raw = [{"type": "Exact", "value": raw}]
    elif isinstance(raw, list):
        raw = [{"type": "Exact", "value": item} if isinstance(item, str) else item for item in raw]
    result: list[MatchValue] = []
    for index, item in enumerate(_sequence(raw, label)):
        entry = _mapping(item, f"{label}[{index}]")
        kind = _text(entry.get("type"), f"{label}[{index}].type", "Exact")
        if kind not in MATCH_TYPES:
            raise ManifestError(f"{label}[{index}].type: unsupported match type {kind!r}")
        value = _text(entry.get("value"), f"{label}[{index}].value")
        if kind != "Present" and not value:
            raise ManifestError(f"{label}[{index}].value: required for {kind}")
        if kind == "RegularExpression":
            _regex(value, f"{label}[{index}].value")
        result.append(MatchValue(kind, value if kind != "Present" else None))
    return tuple(result) if result else (MatchValue("Present", None),)


def _named_matches(raw: Any, label: str) -> tuple[HeaderMatch, ...]:
    result: list[HeaderMatch] = []
    for index, item in enumerate(_sequence(raw, label)):
        entry = _mapping(item, f"{label}[{index}]")
        name = _text(entry.get("name"), f"{label}[{index}].name").lower()
        if not name:
            raise ManifestError(f"{label}[{index}].name: required")
        result.append(
            HeaderMatch(name, _value_matches(entry.get("value"), f"{label}[{index}].value"))
        )
    return tuple(result)


def _route_match(raw: Any, label: str) -> RouteMatch:
    entry = _mapping(raw, label)
    path_raw = _mapping(entry.get("path") or {}, f"{label}.path")
    kind = _text(path_raw.get("type"), f"{label}.path.type", "PathPrefix")
    if kind not in PATH_TYPES:
        raise ManifestError(f"{label}.path.type: unsupported path type {kind!r}")
    value = _text(path_raw.get("value"), f"{label}.path.value", "/")
    if not value:
        value = "/"
    if kind == "RegularExpression":
        _regex(value, f"{label}.path.value")
    method = _text(entry.get("method"), f"{label}.method").upper()
    return RouteMatch(
        PathMatch(kind, value),
        _named_matches(entry.get("headers"), f"{label}.headers"),
        _named_matches(entry.get("queryParams"), f"{label}.queryParams"),
        method or None,
    )


def _route(raw: dict[str, Any], source: str, order: int) -> HttpRoute:
    metadata = _mapping(raw.get("metadata"), "HTTPRoute.metadata")
    name = _text(metadata.get("name"), "HTTPRoute.metadata.name")
    if not name:
        raise ManifestError(f"{source}: HTTPRoute.metadata.name is required")
    namespace = (
        _text(metadata.get("namespace"), "HTTPRoute.metadata.namespace", "default") or "default"
    )
    spec = _mapping(raw.get("spec"), "HTTPRoute.spec")

    parents: list[ParentRef] = []
    for index, item in enumerate(_sequence(spec.get("parentRefs"), "HTTPRoute.spec.parentRefs")):
        entry = _mapping(item, f"parentRefs[{index}]")
        parent_name = _text(entry.get("name"), f"parentRefs[{index}].name")
        if not parent_name:
            raise ManifestError(f"{source}: parentRefs[{index}].name is required")
        parents.append(
            ParentRef(
                parent_name,
                _text(entry.get("namespace"), f"parentRefs[{index}].namespace") or None,
                _text(entry.get("sectionName"), f"parentRefs[{index}].sectionName") or None,
                _port(entry.get("port"), f"parentRefs[{index}].port"),
            )
        )

    hostnames_list: list[str] = []
    for index, item in enumerate(_sequence(spec.get("hostnames"), "HTTPRoute.spec.hostnames")):
        value = hostnames.normalize(_text(item, f"hostnames[{index}]"))
        if not hostnames.is_valid(value):
            raise ManifestError(f"{source}: invalid hostname {item!r}")
        hostnames_list.append(value)

    rules: list[Rule] = []
    for index, item in enumerate(_sequence(spec.get("rules"), "HTTPRoute.spec.rules")):
        entry = _mapping(item, f"rules[{index}]")
        default_match = {"path": {"type": "PathPrefix", "value": "/"}}
        match_raw = entry.get("matches") or [default_match]
        matches = tuple(
            _route_match(match, f"rules[{index}].matches[{pos}]")
            for pos, match in enumerate(_sequence(match_raw, f"rules[{index}].matches"))
        )
        backends: list[BackendRef] = []
        for pos, backend in enumerate(
            _sequence(entry.get("backendRefs"), f"rules[{index}].backendRefs")
        ):
            item_map = _mapping(backend, f"backendRefs[{pos}]")
            backend_name = _text(item_map.get("name"), f"backendRefs[{pos}].name")
            if not backend_name:
                raise ManifestError(f"{source}: backendRefs[{pos}].name is required")
            backends.append(
                BackendRef(
                    backend_name,
                    _text(item_map.get("namespace"), f"backendRefs[{pos}].namespace") or None,
                    _port(item_map.get("port"), f"backendRefs[{pos}].port"),
                )
            )
        rules.append(Rule(index, matches, tuple(backends)))

    return HttpRoute(
        name,
        namespace,
        tuple(parents),
        tuple(hostnames_list),
        tuple(rules),
        _text(metadata.get("creationTimestamp"), "HTTPRoute.metadata.creationTimestamp"),
        order,
        source,
    )


def _gateway(raw: dict[str, Any], source: str) -> Gateway:
    metadata = _mapping(raw.get("metadata"), "Gateway.metadata")
    name = _text(metadata.get("name"), "Gateway.metadata.name")
    if not name:
        raise ManifestError(f"{source}: Gateway.metadata.name is required")
    namespace = (
        _text(metadata.get("namespace"), "Gateway.metadata.namespace", "default") or "default"
    )
    spec = _mapping(raw.get("spec"), "Gateway.spec")
    listeners: list[Listener] = []
    for index, item in enumerate(_sequence(spec.get("listeners"), "Gateway.spec.listeners")):
        entry = _mapping(item, f"listeners[{index}]")
        listener_name = _text(entry.get("name"), f"listeners[{index}].name")
        if not listener_name:
            raise ManifestError(f"{source}: listeners[{index}].name is required")
        protocol = _text(entry.get("protocol"), f"listeners[{index}].protocol", "HTTP") or "HTTP"
        port = _port(entry.get("port"), f"listeners[{index}].port")
        if port is None:
            raise ManifestError(f"{source}: listeners[{index}].port is required")
        hostname_raw = _text(entry.get("hostname"), f"listeners[{index}].hostname")
        hostname = hostnames.normalize(hostname_raw) or None
        if hostname is not None and not hostnames.is_valid(hostname):
            raise ManifestError(f"{source}: invalid listener hostname {hostname_raw!r}")
        allowed = _mapping(entry.get("allowedRoutes") or {}, f"listeners[{index}].allowedRoutes")
        namespaces_rule = _mapping(
            allowed.get("namespaces") or {}, f"listeners[{index}].allowedRoutes.namespaces"
        )
        allowed_from = (
            _text(namespaces_rule.get("from"), "allowedRoutes.namespaces.from", "Same") or "Same"
        )
        if allowed_from not in {"Same", "Selector", "All"}:
            raise ManifestError(f"{source}: unsupported allowedRoutes.from {allowed_from!r}")
        selector = _mapping(
            namespaces_rule.get("selector") or {}, "allowedRoutes.namespaces.selector"
        )
        labels = {
            str(key): str(value)
            for key, value in _mapping(
                selector.get("matchLabels") or {}, "selector.matchLabels"
            ).items()
        }
        expressions: list[SelectorExpression] = []
        for pos, expr in enumerate(
            _sequence(selector.get("matchExpressions"), "selector.matchExpressions")
        ):
            expr_map = _mapping(expr, f"matchExpressions[{pos}]")
            operator = _text(expr_map.get("operator"), f"matchExpressions[{pos}].operator")
            if operator not in OPERATORS:
                raise ManifestError(f"{source}: unsupported selector operator {operator!r}")
            expressions.append(
                SelectorExpression(
                    _text(expr_map.get("key"), f"matchExpressions[{pos}].key"),
                    operator,
                    tuple(
                        str(item) for item in _sequence(expr_map.get("values"), "expression.values")
                    ),
                )
            )
        kinds: list[KindConstraint] = []
        for pos, kind in enumerate(_sequence(allowed.get("kinds"), "allowedRoutes.kinds")):
            kind_map = _mapping(kind, f"kinds[{pos}]")
            kinds.append(
                KindConstraint(
                    _text(kind_map.get("group"), f"kinds[{pos}].group"),
                    _text(kind_map.get("kind"), f"kinds[{pos}].kind"),
                )
            )
        listeners.append(
            Listener(
                listener_name,
                protocol,
                port,
                hostname,
                allowed_from,
                labels,
                tuple(expressions),
                tuple(kinds),
                name,
                namespace,
                source,
            )
        )
    return Gateway(name, namespace, tuple(listeners), source)


def _namespace(raw: dict[str, Any], source: str) -> Namespace:
    metadata = _mapping(raw.get("metadata"), "Namespace.metadata")
    name = _text(metadata.get("name"), "Namespace.metadata.name")
    if not name:
        raise ManifestError(f"{source}: Namespace.metadata.name is required")
    labels = {
        str(key): str(value)
        for key, value in _mapping(
            metadata.get("labels") or {}, "Namespace.metadata.labels"
        ).items()
    }
    return Namespace(name, labels)


def _source_files(paths: list[Path]) -> list[Path]:
    found: set[Path] = set()
    for path in paths:
        if path.is_file():
            found.add(path.resolve())
            continue
        if not path.is_dir():
            raise ManifestError(f"input path does not exist: {path}")
        for pattern in ("*.yaml", "*.yml", "*.json"):
            found.update(item.resolve() for item in path.rglob(pattern) if item.is_file())
    return sorted(found)


def parse_manifests(inputs: list[str] | list[Path]) -> ManifestSet:
    sources = _source_files([Path(item) for item in inputs])
    if not sources:
        raise ManifestError("no manifest files found")

    gateways: list[Gateway] = []
    routes: list[HttpRoute] = []
    namespaces: list[Namespace] = []
    documents = 0
    skipped = 0
    for source in sources:
        try:
            text = source.read_text(encoding="utf-8")
            documents_batch = list(yaml.safe_load_all(text))
        except (OSError, yaml.YAMLError) as exc:
            raise ManifestError(f"{source}: {exc}") from exc
        for document in documents_batch:
            if document is None:
                continue
            documents += 1
            raw = _mapping(document, f"{source}: document")
            api = _text(raw.get("apiVersion"), f"{source}: apiVersion")
            kind = _text(raw.get("kind"), f"{source}: kind")
            if kind == "Namespace" and api == "v1":
                namespaces.append(_namespace(raw, str(source)))
            elif api != f"{GROUP}/{VERSION}":
                skipped += 1
            elif kind == "Gateway":
                gateways.append(_gateway(raw, str(source)))
            elif kind == "HTTPRoute":
                routes.append(_route(raw, str(source), len(routes)))
            else:
                skipped += 1

    return ManifestSet(
        tuple(gateways),
        tuple(routes),
        tuple(namespaces),
        {
            "files": len(sources),
            "documents": documents,
            "gateways": len(gateways),
            "routes": len(routes),
            "rules": sum(len(route.rules) for route in routes),
            "namespaces": len(namespaces),
            "skipped": skipped,
        },
    )
