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


@dataclass
class Server(BaseConfig):
    listen_ip: str
    listen_port_range: list[int]
    percent_of_open_ports_range: list[float | str]
    ports_lasting_duration_mins_range: list[int]
    serv_win_port: int
    serv_win_duration_mins_range: list[int]
    connect_host: str
    connect_port: int

    log: str
    verbosity: str

    private_key: EccKey | str
    accepted_keys: list[EccKey | str]

    yaml_tag = "!Server"

    def validate(self):
        if (len(self.listen_port_range) != 2 or
                not (0 < self.listen_port_range[0] < 65536) or
                not (0 < self.listen_port_range[1] < 65536) or
                self.listen_port_range[0] > self.listen_port_range[1]
        ):
            raise ValueError("Invalid listen port range")

        if not 0 < self.serv_win_port < 65536:
            raise ValueError("Invalid service window port")

        if (len(self.serv_win_duration_mins_range) != 2 or
                self.serv_win_duration_mins_range[0] > self.serv_win_duration_mins_range[1]
        ):
            raise ValueError("Invalid service window duration range")

        if 30 > self.serv_win_duration_mins_range[0]:
            raise ValueError("Minimum service window duration is 30 mins")

    def post_load(self):
        try:
            self.private_key = ECC.import_key(self.private_key)
            if self.private_key.curve != "Ed25519":
                raise ValueError("Unsupported key type")
            if not self.private_key.has_private():
                raise ValueError("Expected private key, got public key")
        except Exception as e:
            e.add_note("Field private_key must be importable Ed25519 private key in ASCII")
            raise

        kstrs = self.accepted_keys
        self.accepted_keys = []
        for i in range(len(kstrs)):
            kstr = kstrs[i]
            try:
                k = ECC.import_key(kstr)
                if k.curve != "Ed25519":
                    raise ValueError("Unsupported key type")
                if k.has_private():
                    raise ValueError("Expected public key, got private key")
                self.accepted_keys.append(k)
            except Exception as e:
                e.add_note("Field accepted_keys must be a list of importable Ed25519 public keys in ASCII")
                e.add_note(f"In #{i} item of field accepted_keys")
                raise

        msg = "Field percent_of_open_ports_range must be a list of 2 percentages (e.g. 0.58 or 58%)"
        if len(self.percent_of_open_ports_range) != 2:
            raise ValueError(msg)
        for i in range(len(self.percent_of_open_ports_range)):
            r = self.percent_of_open_ports_range
            p = r[i]
            if isinstance(p, str):
                if p[-1] != "%":
                    raise ValueError(msg)
                try:
                    r[i] = float(p[:-1]) / 100
                except Exception as e:
                    e.add_note(msg)
                    raise
            if not 0 < r[i] < 1:
                raise ValueError(msg)
        if self.percent_of_open_ports_range[0] > self.percent_of_open_ports_range[1]:
            raise ValueError(msg)

        if (len(self.ports_lasting_duration_mins_range) != 2 or
                not self.ports_lasting_duration_mins_range[0] <= self.ports_lasting_duration_mins_range[1]):
            raise ValueError("Field ports_lasting_duration_mins_range should be a list of 2 integers.")

        if self.ports_lasting_duration_mins_range[0] < self.serv_win_duration_mins_range[0] * 2:
            e = ValueError("Minimum ports lasting duration is minimum service window duration times 2.")
            e.add_note("It's recommended that ports lasting duration is much longer than service window duration.")
            raise e

    def __getstate__(self):
        d = self.__dict__.copy()
        d["private_key"] = self.private_key.export_key(format="PEM")
        d["accepted_keys"] = l = []
        for k in self.accepted_keys:
            l.append(k.export_key(format="PEM"))
        return d


def get_default_cfg_paths(name: Literal["py225", "py225d", "py225-gui"]) -> list[str]:
    dirs = []
    match sys.platform:
        case "linux":
            if os.getenv("XDG_DATA_HOME"):
                dirs.append(os.getenv("XDG_DATA_HOME") + "/py225")
            elif os.getenv("HOME"):
                dirs.append(os.getenv("HOME") + "/.local/share/py225")
            dirs.append("/etc")
        case "win32":
            if os.getenv("LocalAppData"):
                dirs.append(os.getenv("LocalAppData") + "\\py225")
    dirs.append(os.getcwd())
    if getattr(sys, 'frozen', False):
        dirs.append(os.path.dirname(sys.executable))
    else:
        script_path = os.path.abspath(sys.argv[0])
        dirs.append(os.path.dirname(script_path))

    paths = []
    for dir in dirs:
        paths.append(os.path.join(dir, name + ".yaml"))
        paths.append(os.path.join(dir, name + ".yml"))

    return paths


# TODO: Add limit config file permission on Linux
def load(p, name):
    paths = [p] if p is not None else get_default_cfg_paths(name)
    loaded = False
    for path in paths:
        try:
            with open(path) as f:
                data = f.read()
            cfg = yaml.safe_load(data)
            cfg.validate()
            cfg.post_load()
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
