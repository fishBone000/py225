from dataclasses import dataclass, field

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
