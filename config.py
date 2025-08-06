from dataclasses import dataclass
import yaml
from base64 import b64decode


@dataclass
class Server(yaml.YAMLObject):
    private_key: bytes
    host_public_key: bytes | None
    yaml_loader = yaml.SafeLoader

@dataclass
class Config(yaml.YAMLObject):
    servers: dict[str, Server]
    yaml_loader = yaml.SafeLoader

    @classmethod
    def load(cls, file_path):
        with open(file_path, "r") as f:
            yml = yaml.safe_load(f)
        servers = {host: Server(b64decode(server_cfg["private key"]), b64decode(server_cfg["host public key"])) for
                   host, server_cfg in
                   yml["servers"]}
        return cls(servers)
