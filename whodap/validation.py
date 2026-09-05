from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft7Validator, FormatChecker, ValidationError
from jsonschema.exceptions import best_match
from referencing import Registry
from referencing.jsonschema import DRAFT7

from .errors import RDAPConformanceException

FORMAT_CHECKER = FormatChecker()

_SUPPORTED_EXTENSION_PREFIXES = ("rdap_level_", "icann_rdap_", "nro_rdap_")
_SCHEMA_ROOT = Path(__file__).resolve().parent / "schemas"
_ROOT_URI = f"{_SCHEMA_ROOT.as_uri()}/"


def _strip_nested_ids(node: Any, *, is_root: bool = False) -> Any:
    if isinstance(node, dict):
        cleaned = {}
        for key, value in node.items():
            if key == "$id" and not is_root:
                continue
            cleaned[key] = _strip_nested_ids(value)
        return cleaned
    if isinstance(node, list):
        return [_strip_nested_ids(item) for item in node]
    return node


def _is_valid_idn_hostname(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False

    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        return False

    total_length = 0
    try:
        for label in labels:
            if not label:
                return False
            ascii_label = label.encode("idna").decode("ascii")
            if len(ascii_label) > 63:
                return False
            total_length += len(ascii_label) + 1
    except UnicodeError:
        return False

    return total_length - 1 <= 253


@FORMAT_CHECKER.checks("idn-hostname")
def _check_idn_hostname(value: object) -> bool:
    return _is_valid_idn_hostname(value)


@FORMAT_CHECKER.checks("hostname-in-uri")
def _check_hostname_in_uri(value: object) -> bool:
    if not isinstance(value, str):
        return False

    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        return False

    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass

    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        pass

    return _is_valid_idn_hostname(host)


@FORMAT_CHECKER.checks("ipv4-validation")
def _check_ipv4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


@FORMAT_CHECKER.checks("ipv6-validation")
def _check_ipv6(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


@FORMAT_CHECKER.checks("rdapExtensions")
def _check_rdap_extensions(value: object) -> bool:
    return isinstance(value, str) and value.startswith(_SUPPORTED_EXTENSION_PREFIXES)


@lru_cache(maxsize=1)
def _schema_store() -> tuple[dict[str, Any], dict[str, Draft7Validator]]:
    raw_schemas: dict[str, Any] = {}
    validators: dict[str, Draft7Validator] = {}
    registry = Registry()

    for schema_path in _SCHEMA_ROOT.rglob("*.json"):
        relative_name = schema_path.relative_to(_SCHEMA_ROOT).as_posix()
        schema = _strip_nested_ids(
            json.loads(schema_path.read_text(encoding="utf-8")),
            is_root=True,
        )
        raw_schemas[relative_name] = schema

        resource = DRAFT7.create_resource(schema)
        registry = registry.with_resource(relative_name, resource)
        registry = registry.with_resource(f"{_ROOT_URI}{relative_name}", resource)
        if schema.get("$id"):
            schema_id = str(schema["$id"])
            registry = registry.with_resource(schema_id, resource)
            registry = registry.with_resource(f"{_ROOT_URI}{schema_id}", resource)

    for schema_name, schema in raw_schemas.items():
        validators[schema_name] = Draft7Validator(
            schema,
            registry=registry,
            format_checker=FORMAT_CHECKER,
        )

    return raw_schemas, validators


def _format_json_pointer(error: ValidationError) -> str:
    if not error.absolute_path:
        return "#"
    return "#/" + "/".join(str(part) for part in error.absolute_path)


def validate_rdap_payload(payload: dict[str, Any], schema_name: str) -> None:
    _, validators = _schema_store()
    validator = validators[schema_name]
    error = best_match(validator.iter_errors(payload))
    if error is None:
        return

    pointer = _format_json_pointer(error)
    raise RDAPConformanceException(f"{pointer}: {error.message}")
