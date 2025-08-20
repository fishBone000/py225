import unittest

import yaml
from Crypto.PublicKey.ECC import generate, EccKey

import config


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
        def gen():
            return generate(curve="Ed25519")
        default_key = gen()
        priv_keys = [default_key, gen()]
        pub_keys = [gen(), None]
        expected = config.Client(
            [config.ServerRecord("google.com", 443, priv_keys[0], pub_keys[0]),
             config.ServerRecord("cloudflare.com", 888, priv_keys[1], pub_keys[1])
             ],
            "stderr","warning", "127.0.0.1", 1080, default_key
        )

        def export(k: EccKey, indent: int = 1):
            s = k.export_key(format="PEM")
            return ("\n\n" + "  "*indent).join(s.split("\n"))

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