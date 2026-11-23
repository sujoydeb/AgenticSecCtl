"""Typed, layered, validated configuration (WP-1.2, cross-cutting design Section 6, TC-Z10).

Layers, lowest to highest precedence: built-in defaults, file, environment.
Hard bounds (``min``/``max``) live in the schema in code, so configuration can
never loosen a control beyond them. Secrets are references (``secretref:...``)
resolved only at the moment of use; a raw secret value is refused. Errors name
the key and the rule, never the offending value.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize, sha256_hex

_MISSING = object()
SECRET_PREFIX = "secretref:"  # noqa: S105 - a marker, not a secret
_TRUE, _FALSE = {"true", "1", "yes", "on"}, {"false", "0", "no", "off"}


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Field:
    type: type
    default: Any = _MISSING
    min: float | None = None
    max: float | None = None
    secret: bool = False


class Schema:
    def __init__(self, fields: Mapping[str, Field]):
        self.fields = dict(fields)


def _coerce_env(name: str, f: Field, raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        if f.type is bool:
            low = raw.strip().lower()
            if low in _TRUE:
                return True
            if low in _FALSE:
                return False
            raise ValueError
        if f.type in (int, float):
            return f.type(raw.strip())
    except ValueError:
        raise ConfigError([f"{name}: not a valid {f.type.__name__}"]) from None
    return raw


def _check(name: str, f: Field, v: Any) -> str | None:
    if f.type is float and isinstance(v, int) and not isinstance(v, bool):
        v = float(v)
    if not isinstance(v, f.type) or (f.type is int and isinstance(v, bool)):
        return f"{name}: expected {f.type.__name__}"
    if f.secret and not (isinstance(v, str) and v.startswith(SECRET_PREFIX) and len(v) > len(SECRET_PREFIX)):
        return f"{name}: must be a secret reference ({SECRET_PREFIX}...), not a value"
    if f.min is not None and isinstance(v, (int, float)) and v < f.min:
        return f"{name}: below the minimum"
    if f.max is not None and isinstance(v, (int, float)) and v > f.max:
        return f"{name}: above the maximum"
    return None


class Config:
    def __init__(self, schema: Schema, values: dict[str, Any]):
        self._schema = schema
        self.values = values
        self.version_hash = sha256_hex(canonicalize(values))

    def secret(self, name: str, resolver: Callable[[str], str]) -> str:
        if not self._schema.fields[name].secret:
            raise KeyError(name)
        return resolver(self.values[name][len(SECRET_PREFIX):])

    def public_view(self) -> dict[str, Any]:
        return dict(self.values)  # secrets are references only

    def __repr__(self) -> str:
        return f"Config(version_hash={self.version_hash[:12]})"


def load_config(schema: Schema, *, file: Mapping[str, Any], env: Mapping[str, Any]) -> Config:
    errors: list[str] = []
    for layer_name, layer in (("file", file), ("env", env)):
        for k in layer:
            if k not in schema.fields:
                errors.append(f"{layer_name}: unknown key '{k}'")
    values: dict[str, Any] = {}
    for name, f in schema.fields.items():
        try:
            if name in env:
                raw = _coerce_env(name, f, env[name])
            elif name in file:
                raw = file[name]
            elif f.default is not _MISSING:
                raw = f.default
            else:
                errors.append(f"{name}: required")
                continue
        except ConfigError as e:
            errors.extend(e.errors)
            continue
        err = _check(name, f, raw)
        if err:
            errors.append(err)
        else:
            values[name] = float(raw) if f.type is float else raw
    if errors:
        raise ConfigError(errors)
    return Config(schema, values)


def env_layer(environ: Mapping[str, str], prefix: str) -> dict[str, str]:
    """Map PREFIX_KEY=value to {key: value}; unknown keys then fail validation."""
    p = prefix.upper() + "_"
    return {k[len(p):].lower(): v for k, v in environ.items() if k.startswith(p)}


def config_changed_event(old: Config, new: Config, *, actor: str) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for name, f in new._schema.fields.items():
        if old.values.get(name) != new.values.get(name):
            changes[name] = ({"changed": True} if f.secret
                             else {"old": old.values.get(name), "new": new.values.get(name)})
    return {"event": "config.changed", "actor": actor, "old_hash": old.version_hash,
            "new_hash": new.version_hash, "changes": changes}


class ConfigHolder:
    """Holds the applied configuration; an invalid reload keeps the last valid one."""

    def __init__(self, schema: Schema, current: Config):
        self._schema, self.current, self._lock = schema, current, threading.Lock()

    @classmethod
    def start(cls, schema: Schema, *, file: Mapping[str, Any], env: Mapping[str, Any]) -> ConfigHolder:
        return cls(schema, load_config(schema, file=file, env=env))  # raises: the service must not start

    def reload(self, *, file: Mapping[str, Any], env: Mapping[str, Any],
               actor: str = "system") -> ConfigError | dict[str, Any] | None:
        try:
            new = load_config(self._schema, file=file, env=env)
        except ConfigError as e:
            return e
        with self._lock:
            if new.version_hash == self.current.version_hash:
                return None
            event = config_changed_event(self.current, new, actor=actor)
            self.current = new
            return event
