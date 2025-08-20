from __future__ import annotations

import os
import sys
import typing
from dataclasses import dataclass, field
from types import GenericAlias
from typing import Literal

import yaml
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey


class BaseConfig(yaml.YAMLObject):
    yaml_loader = yaml.SafeLoader
    yaml_dumper = yaml.SafeDumper
    inherited_fields = set()

    def inherit(self, parent: BaseConfig):
        """
        Inherit fields from parent config if the field is not set in this object and is set in parent config
        :param parent: Config that is 1 level up.
        """
        for ihf in self.inherited_fields:
            if hasattr(parent, ihf) and (not hasattr(self, ihf) or getattr(self, ihf) is None):
                setattr(self, ihf, getattr(parent, ihf))

    def post_load(self):
        """
        Iterate over all fields that are instance of ``AbstractConfig``,
        then calls their ``inherit`` and  ``post_load`` methods.

        Override this method to implement post loading logic.
        """
        for k in self.__dict__:
            v = self.__dict__[k]
            if isinstance(v, BaseConfig):
                try:
                    v.inherit(self)
                    v.post_load()
                except Exception as e:
                    e.add_note(f"In field {k}")
                    raise
            elif isinstance(v, list):
                for i in range(len(v)):
                    inst = v[i]
                    if isinstance(inst, BaseConfig):
                        try:
                            inst.inherit(self)
                            inst.post_load()
                        except Exception as e:
                            e.add_note(f"In #{i} item of field {k}")
                            raise

    def validate(self):
        hints = typing.get_type_hints(type(self))
        for k in hints:
            hint = hints[k]

            # If attribute not present
            if not hasattr(self, k):
                if isinstance(None, hint):  # If field is optional
                    setattr(self, k, None)
                else:
                    raise TypeError(f"Field {k} is mandatory")

            v = getattr(self, k)
            err = TypeError(f"Field {k}: expected type {hint}, got {type(v)}")

            # If is generic type
            if isinstance(hint, GenericAlias):
                o = typing.get_origin(hint)
                if not isinstance(v, o):
                    raise err
                match o:
                    case _ if o is list:
                        arg = typing.get_args(hint)[0]
                        if not all((isinstance(i, arg) for i in v)):
                            raise ValueError(f"Field {k} expects a list of {arg}")

                        if issubclass(arg, BaseConfig):
                            for i in range(len(v)):
                                inst = v[i]
                                try:
                                    inst.validate()
                                except Exception as e:
                                    e.add_note(f"In #{i} of field {k}")
                                    raise
                    case _:
                        raise err
                continue

            # If is primitive types or classes
            if not isinstance(v, hint):
                raise err
            if isinstance(v, BaseConfig):
                try:
                    v.validate()
                except Exception as e:
                    e.add_note(f"In field {k}")
                    raise


@dataclass
class ServerRecord(BaseConfig):
    host: str
    port: int
    private_key: EccKey | str | None = field(repr=False)
    host_public_key: EccKey | str | None = None
    yaml_tag = "!ServerRecord"
    inherited_fields = {"private_key"}

    def validate(self):
        super().validate()
        if not 0 < self.port < 65536:
            raise ValueError("invalid port", self.port)

    def post_load(self):
        if self.private_key is None:
            raise ValueError(f"Field private_key is mandatory")

        if not isinstance(self.private_key, EccKey):
            try:
                self.private_key = ECC.import_key(self.private_key)
                if self.private_key.curve != "Ed25519":
                    raise ValueError("Key must be Ed25519 key")
            except Exception as e:
                e.add_note("field private_key must be importable Ed25519 private key in ASCII")
                raise

        try:
            if self.host_public_key is not None:
                self.host_public_key = ECC.import_key(self.host_public_key)
                if self.host_public_key.curve != "Ed25519":
                    raise ValueError("Key must be Ed25519 key")
        except Exception as e:
            e.add_note("field host_public_key must be importable Ed25519 public key in ASCII")
            raise

    def __getstate__(self):
        d = self.__dict__.copy()
        d["private_key"] = self.private_key.export_key(format="PEM")
        if self.host_public_key is not None:
            d["host_public_key"] = self.host_public_key.export_key(format="PEM")
        return d


@dataclass
class Client(BaseConfig):
    servers: list[ServerRecord]
    log: str
    verbosity: str
    listen_ip: str
    listen_port: int
    private_key: EccKey | str | None = field(repr=False)
    yaml_tag = "!Client"

    def post_load(self):
        if self.private_key is not None:
            msg = "optional field private_key must be importable Ed25519 private key in ASCII or unset"
            try:
                self.private_key = ECC.import_key(self.private_key)
            except Exception as e:
                e.add_note(msg)
                raise

        super().post_load()

    def __getstate__(self):
        d = self.__dict__.copy()
        if self.private_key is not None:
            d["private_key"] = self.private_key.export_key(format="PEM")
        return d



def get_default_cfg_paths(name: Literal["py225", "py225d", "py225-gui"]) -> list[str]:
    dirs = []
    match sys.platform:
        case "linux":
            if os.getenv("XDG_DATA_HOME"):
                dirs.append(os.getenv("XDG_DATA_HOME") + "/py225")
            elif os.getenv("HOME"):
                dirs.append(os.getenv("HOME") + "/.local/share/py225")
        case "win32":
            if os.getenv("LocalAppData"):
                dirs.append(os.getenv("LocalAppData") + "\\py225")
    dirs.append(os.getcwd())
    if getattr(sys, 'frozen', False):
        # PyInstaller 或类似工具生成的 exe 路径
        dirs.append(os.path.dirname(sys.executable))
    else:
        # 普通脚本运行时，获取当前脚本的绝对路径
        script_path = os.path.abspath(sys.argv[0])
        dirs.append(os.path.dirname(script_path))

    paths = []
    for dir in dirs:
        paths.append(os.path.join(dir, name + ".yaml"))
        paths.append(os.path.join(dir, name + ".yml"))

    return paths


def load(p, name):
    paths = [p] if p is not None else get_default_cfg_paths(name)
    loaded = False
    for path in paths:
        try:
            with open(path) as f:
                data = f.read()
            cfg = yaml.safe_load(data)
            if not isinstance(cfg, Client):
                raise ValueError("Bad config format.")
            loaded = True
            break
        except FileNotFoundError:
            pass
        except Exception as e:
            e.add_note(f"When loading {path}")
            raise

    if not loaded:
        raise FileNotFoundError(f"Config file not found in following paths: \n{"\n".join(paths)}")
    return cfg
