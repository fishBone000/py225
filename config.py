import os
import sys
from dataclasses import dataclass, field
from typing import Literal

import yaml
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey


@dataclass
class ServerRecord(yaml.YAMLObject):
    host: str
    port: int
    private_key: EccKey = field(repr=False)
    host_public_key: EccKey | None = None
    yaml_loader = yaml.SafeLoader
    yaml_tag = "!ServerRecord"

    def __setstate__(self, state):
        self.__dict__.update(state)

        if not hasattr(self, "private_key"):
            self.private_key = None
        if not hasattr(self, "host_public_key"):
            self.host_public_key = None

        if type(self.private_key) is str:
            self.private_key = ECC.import_key(self.private_key)
            if self.private_key.curve != "Ed25519":
                raise ValueError("Only Ed25519 keys are supported")
        if type(self.host_public_key) is str:
            self.host_public_key = ECC.import_key(self.host_public_key)
            if self.host_public_key.curve != "Ed25519":
                raise ValueError("Only Ed25519 keys are supported")

        if not 0 < self.port < 65535:
            raise ValueError(f"invalid port {self.port}")


@dataclass
class Client(yaml.YAMLObject):
    servers: list[ServerRecord]
    log: str
    verbosity: str
    listen_ip: str
    listen_port: int
    private_key: EccKey | None = field(repr=False)
    yaml_loader = yaml.SafeLoader
    yaml_tag = "!Client"

    def __setstate__(self, state):
        self.__dict__.update(state)

        if not hasattr(self, "private_key"):
            self.private_key = None

        if type(self.private_key) is str:
            self.private_key = ECC.import_key(self.private_key)
            if self.private_key.curve != "Ed25519":
                raise ValueError("Only Ed25519 keys are supported")

        for rec in self.servers:
            if rec.private_key is None:
                if self.private_key is None:
                    raise ValueError(f"no private key specified for {rec.host} port {rec.port}")
                if self.private_key is not None:
                    rec.private_key = self.private_key


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
