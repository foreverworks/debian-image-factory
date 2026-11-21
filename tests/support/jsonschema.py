"""A small JSON Schema validator for the tests, standard library only.

It covers the keywords SPDX's published 2.3 schema (draft-07) uses, and a few more that schemas of
this kind use: type, properties, required, items, enum, const, pattern, additionalProperties (a
boolean or a schema), minItems, maxItems, minLength, `$ref` to `#/definitions/...`, allOf, anyOf and
oneOf. Annotation keywords (description, comment, title, `$schema`, `$id`, format, default, examples,
definitions) are ignored. A keyword it does not know raises `UnsupportedKeywordError`, so a schema update
that starts using one cannot make this validator quietly more lenient than the schema.
"""

import re
from collections.abc import Mapping, Sequence
from typing import Final

ANNOTATIONS: Final = frozenset(
    {"description", "comment", "title", "$schema", "$id", "format", "default", "examples", "definitions"}
)
KEYWORDS: Final = frozenset(
    {
        "type",
        "properties",
        "required",
        "items",
        "enum",
        "const",
        "pattern",
        "additionalProperties",
        "minItems",
        "maxItems",
        "minLength",
        "$ref",
        "allOf",
        "anyOf",
        "oneOf",
    }
)


class UnsupportedKeywordError(ValueError):
    """The schema uses a keyword this validator does not implement."""


def _is_type(value: object, name: str) -> bool:
    match name:
        case "object":
            return isinstance(value, dict)
        case "array":
            return isinstance(value, list)
        case "string":
            return isinstance(value, str)
        case "boolean":
            return isinstance(value, bool)
        case "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        case "number":
            return isinstance(value, int | float) and not isinstance(value, bool)
        case "null":
            return value is None
    raise UnsupportedKeywordError(f"type {name!r}")


def _resolve(root: Mapping[str, object], reference: str) -> Mapping[str, object]:
    if not reference.startswith("#/"):
        raise UnsupportedKeywordError(f"$ref {reference!r}: only '#/...' pointers are supported")
    node: object = root
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"$ref {reference!r} points at nothing")
        node = node[part]
    if not isinstance(node, dict):
        raise ValueError(f"$ref {reference!r} is not a schema")
    return {str(key): value for key, value in node.items()}


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object in the schema")
    return {str(key): item for key, item in value.items()}


def _list(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{where} must be an array in the schema")
    return list(value)


def _check(value: object, schema: Mapping[str, object], root: Mapping[str, object], path: str) -> list[str]:
    """Every way `value` breaks `schema`; `path` says where in the instance it is."""
    errors: list[str] = []
    for keyword, rule in schema.items():
        if keyword in ANNOTATIONS:
            continue
        if keyword not in KEYWORDS:
            raise UnsupportedKeywordError(keyword)
        errors.extend(_keyword(keyword, rule, value, schema, root, path))
    return errors


def _keyword(
    keyword: str, rule: object, value: object, schema: Mapping[str, object], root: Mapping[str, object], path: str
) -> list[str]:
    where = path or "$"
    errors: list[str] = []
    match keyword:
        case "type":
            names = [rule] if isinstance(rule, str) else _list(rule, "type")
            if not any(_is_type(value, str(name)) for name in names):
                errors.append(f"{where}: expected {rule}, found {type(value).__name__}")
        case "enum":
            if value not in _list(rule, "enum"):
                errors.append(f"{where}: {value!r} is not one of {rule}")
        case "const":
            if value != rule:
                errors.append(f"{where}: {value!r} is not {rule!r}")
        case "pattern":
            if isinstance(value, str) and re.search(str(rule), value) is None:
                errors.append(f"{where}: {value!r} does not match {rule}")
        case "minLength":
            if isinstance(value, str) and isinstance(rule, int) and len(value) < rule:
                errors.append(f"{where}: shorter than {rule} characters")
        case "$ref":
            errors.extend(_check(value, _resolve(root, str(rule)), root, path))
        case "allOf":
            for one in _list(rule, "allOf"):
                errors.extend(_check(value, _mapping(one, "allOf"), root, path))
        case "anyOf" | "oneOf":
            branches = [_check(value, _mapping(one, keyword), root, path) for one in _list(rule, keyword)]
            matching = sum(1 for found in branches if not found)
            if matching == 0 or (keyword == "oneOf" and matching > 1):
                errors.append(f"{where}: matches {matching} of the {keyword} branches")
        case "minItems" | "maxItems" | "items":
            if isinstance(value, list):
                errors.extend(_array(keyword, rule, list(value), root, path))
        case "required" | "properties" | "additionalProperties":
            if isinstance(value, dict):
                found = {str(name): item for name, item in value.items()}
                errors.extend(_object(keyword, rule, found, schema, root, path))
    return errors


def _array(keyword: str, rule: object, value: Sequence[object], root: Mapping[str, object], path: str) -> list[str]:
    where = path or "$"
    if keyword == "items":
        sub = _mapping(rule, "items")
        return [e for index, item in enumerate(value) for e in _check(item, sub, root, f"{path}[{index}]")]
    if keyword == "minItems" and isinstance(rule, int) and len(value) < rule:
        return [f"{where}: fewer than {rule} items"]
    if keyword == "maxItems" and isinstance(rule, int) and len(value) > rule:
        return [f"{where}: more than {rule} items"]
    return []


def _object(
    keyword: str,
    rule: object,
    value: Mapping[str, object],
    schema: Mapping[str, object],
    root: Mapping[str, object],
    path: str,
) -> list[str]:
    where = path or "$"
    errors: list[str] = []
    if keyword == "required":
        errors.extend(f"{where}: missing {name!r}" for name in _list(rule, "required") if name not in value)
    elif keyword == "properties":
        for name, sub in _mapping(rule, "properties").items():
            if name in value:
                errors.extend(_check(value[name], _mapping(sub, f"properties.{name}"), root, f"{path}.{name}"))
    else:
        listed = _mapping(schema.get("properties", {}), "properties")
        for name, item in value.items():
            if name in listed:
                continue
            if rule is False:
                errors.append(f"{where}: unexpected property {name!r}")
            elif isinstance(rule, dict):
                errors.extend(_check(item, _mapping(rule, "additionalProperties"), root, f"{path}.{name}"))
    return errors


def validate(instance: object, schema: Mapping[str, object]) -> list[str]:
    """Every way `instance` breaks `schema`, as readable lines; empty when it conforms."""
    return _check(instance, schema, schema, "")
