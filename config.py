import inspect
import types
import typing
from dataclasses import dataclass, field
from typing import Callable, Any

import yaml
from base64 import b64decode

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from protocol.util import import_raw_ed25519_public_key


class YamlLoadError(Exception):
    pass

@dataclass
class _YamlField[T, T2]:
    converter: Callable[[T2], T] | None = None


def _gen_yaml_key(var_name: str):
    return var_name.replace("_", " ")


def _type_name(a: type):
    assert isinstance(a, type)

    if a is str:
        return "string"
    if hasattr(a, "__name__"):
        return a.__name__
    return str(a)


def _is_primitive(a: type):
    return a in (str, int, float, bool, type(None))


def _load_yaml(a: type, yml: Any):
    """
    Loads YAML, primarily for loading YAML into classes.

    Supports ``int``, ``float``, ``str``, ``X | None``, ``list[X]`` and classes.
    :param a: Expected type of the result.
    :param yml: Object returned by `yaml.safe_load()`.
    :raises TypeError: If argument a is of unsupported type.
    :raises YamlLoadError: If any other problem occurs.
    :return: Value of type `a`.
    """

    # isinstance raises errors on some circumstances, e.g. when classinfo is GenericType
    try:
        if isinstance(yml, a):
            return yml
    except:
        pass

    if _is_primitive(a):
        raise YamlLoadError(f"expected {_type_name(a)} but got {_type_name(type(yml))}")

    if a is list or typing.get_origin(a) is list:
        if type(yml) is not list:
            raise YamlLoadError(f"expected list but got {_type_name(type(a))}")
        if a is list:
            return yml
        args = typing.get_args(a)
        if len(args) > 1 or not (_is_primitive(args[0]) and args[0] is not type(None)) and not isinstance(args[0], type):
            raise TypeError(f"unsupported type {a}")
        l = []
        errors = []
        for i, v in yml:
            try:
                l.append(_load_yaml(args[0], v))
            except Exception as e:
                e.add_note(f"when loading item #{i} of the list")
                errors.append(e)
        if len(errors) > 0:
            raise ExceptionGroup("when building a list", errors)
        return l

    if isinstance(a, type):
        try:
            obj = a.__new__(a)
        except Exception as e:
            raise YamlLoadError(f"couldn't instantiate {a} via __new__") from e

        fields = {name: getattr(a, name) for name in dir(a) if isinstance(getattr(a, name), _YamlField) and name in a.__annotations__}
        annotations = {name: a.__annotations__[name] for name in fields}
        errors = []
        for name in fields:
            key = _gen_yaml_key(name)
            v = yml.get(key)
            t = annotations[name]
            convert = fields[name].converter

            if convert is not None:
                try:
                    v = convert(v)
                except Exception as e:
                    e1 = YamlLoadError(f"failed to convert from {_type_name(v)} to {_type_name(a)}")
                    e1.__cause__ = e
                    e1.add_note(f"for field \"{key}\"")
                    errors.append(e1)
                    continue

            try:
                v = _load_yaml(t, v)
            except Exception as e:
                e1 = YamlLoadError()
                e1.__cause__ = e
                e1.add_note(f"for field \"{key}\"")
                errors.append(e1)
                continue

            setattr(obj, name, v)

        if len(errors) > 0:
            eg = ExceptionGroup(f"failed to load YAML into {a}", errors)
            raise eg

        return obj

    raise YamlLoadError(f"unsupported type {a}")


class ServerRecord:
    host: str = _YamlField()
    port: int = _YamlField()
    private_key: EccKey = _YamlField(ECC.import_key)
    host_public_key: EccKey | None = _YamlField(lambda x: ECC.import_key(x) if x is not None else None)


class Client:
    servers: list[ServerRecord] = _YamlField()
    log: [str] = _YamlField()
    private_key: EccKey | None = _YamlField(ECC.import_key)

    @classmethod
    def load(cls, file_path):
        with open(file_path, "r") as f:
            yml = yaml.safe_load(f)
        return _load_yaml(cls, yml)
