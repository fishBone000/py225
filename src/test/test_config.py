import unittest

import yaml
from Crypto.PublicKey.ECC import generate, EccKey

from py225 import config


def gen():
    return generate(curve="Ed25519")


def export(k: EccKey, indent: int = 1):
    s = k.export_key(format="PEM")
    return ("\n\n" + "  " * indent).join(s.split("\n"))


class TestLoadingYamlConfig(unittest.TestCase):
    def test_client_dump(self):
        """
        Tests config.Client dumps correctly
        """

        def gen():
            return generate(curve="Ed25519")

        cfg = config.Client(
            [config.ServerRecord("google.com", 443, gen(), gen().public_key()),
             config.ServerRecord("cloudflare.com", 888, gen(), None)
             ],
            "stderr", "warning", "127.0.0.1", 1080, gen()
        )
        yml = yaml.safe_dump(cfg)
        print(yml)
        cfg2 = yaml.safe_load(yml)
        cfg2.validate()
        cfg2.post_load()
        self.assertEqual(cfg, cfg2)

    def test_client_load(self):
        default_key = gen()
        priv_keys = [default_key, gen()]
        pub_keys = [gen(), None]
        expected = config.Client(
            [config.ServerRecord("google.com", 443, priv_keys[0], pub_keys[0]),
             config.ServerRecord("cloudflare.com", 888, priv_keys[1], pub_keys[1])
             ],
            "stderr", "warning", "127.0.0.1", 1080, default_key
        )

        yml = f"""
!Client
listen_ip: 127.0.0.1
listen_port: 1080
log: stderr
private_key: '{export(default_key)}'
servers:
- !ServerRecord
  host: google.com
  host_public_key: '{export(pub_keys[0], 2)}'
  port: 443
- !ServerRecord
  host: cloudflare.com
  host_public_key: null
  port: 888
  private_key: '{export(priv_keys[1], 2)}'
verbosity: warning
"""
        print(yml)
        cfg = yaml.safe_load(yml)
        cfg.validate()
        cfg.post_load()

        self.assertEqual(expected, cfg)

    def test_server_load(self):
        priv_key = gen()
        accepted_keys = [gen().public_key() for _ in range(3)]
        yml = f"""
!Server
listen_ip: 0.0.0.0
listen_port_range: [40000, 45000]
ports_lasting_duration_mins_range: [600, 1200]
percent_of_open_ports_range: [30%, 50%]
serv_win_port: 1888
serv_win_duration_mins_range: [60, 120]
connect_host: 127.0.0.1
connect_port: 3000

log: syslog
verbosity: info

private_key: '{export(priv_key, 1)}'
accepted_keys: 
- '{export(accepted_keys[0], 1)}'
- '{export(accepted_keys[1], 1)}'
- '{export(accepted_keys[2], 1)}'
"""

        expected = config.Server("0.0.0.0", [40000, 45000], [0.3, 0.5], [600, 1200], 1888, [60, 120], "127.0.0.1", 3000,
                                 "syslog", "info", priv_key, accepted_keys)
        cfg = yaml.safe_load(yml)
        cfg.validate()
        cfg.post_load()
        self.assertEqual(expected, cfg)

    def test_server_dump(self):
        priv_key = gen()
        accepted_keys = [gen().public_key() for _ in range(3)]

        expected = config.Server("0.0.0.0", [40000, 45000], [0.3, 0.5], [600, 1200], 1888, [60, 120], "127.0.0.1", 3000,
                                 "syslog", "info", priv_key, accepted_keys)
        yml = yaml.safe_dump(expected)
        cfg = yaml.safe_load(yml)
        cfg.validate()
        cfg.post_load()
        self.assertEqual(expected, cfg)
