import unittest

import yaml
from Crypto.PublicKey import ECC

import config


class TestLoadingYamlConfig(unittest.TestCase):
    def test_client_simple(self):
        """
        Tests if ``_load_yaml`` loads a simple YAML client config
        """
        cfg = """
        !Client
        servers: 
          - !ServerRecord
            host: example.com
            port: 9000
          - !ServerRecord
            host: s1.example.com
            port: 9005
            private_key: |
              -----BEGIN PRIVATE KEY-----
              MC4CAQAwBQYDK2VwBCIEING/rSmw5/fC905ZLzmdT+3L2L4RgFeORXSN7iMdxyXU
              -----END PRIVATE KEY-----
            host_public_key: |
              -----BEGIN PUBLIC KEY-----
              MCowBQYDK2VwAyEAmbPDBnrb750SqEzzNNMSSNdPxRjg+PrC4jJ3hocADoo=
              -----END PUBLIC KEY-----
        log: 
          - syslog
        private_key: |
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIKipm4URANeuFgVgeIqzIMIZGdyw2UEMnqCbupcGep73
          -----END PRIVATE KEY-----
        """

        expected_servers = [
            config.ServerRecord("example.com", 9000, ECC.import_key("""
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIKipm4URANeuFgVgeIqzIMIZGdyw2UEMnqCbupcGep73
        -----END PRIVATE KEY-----""".strip()), None),
            config.ServerRecord("s1.example.com", 9005, ECC.import_key("""
                    -----BEGIN PRIVATE KEY-----
                   MC4CAQAwBQYDK2VwBCIEING/rSmw5/fC905ZLzmdT+3L2L4RgFeORXSN7iMdxyXU
                   -----END PRIVATE KEY-----""".strip()), ECC.import_key("""
                   -----BEGIN PUBLIC KEY-----
                   MCowBQYDK2VwAyEAmbPDBnrb750SqEzzNNMSSNdPxRjg+PrC4jJ3hocADoo=
                   -----END PUBLIC KEY-----""".strip()))
        ]
        expected = config.Client(expected_servers, ["syslog"], ECC.import_key("""
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIKipm4URANeuFgVgeIqzIMIZGdyw2UEMnqCbupcGep73
        -----END PRIVATE KEY-----""".strip()))

        yml = yaml.safe_load(cfg)
        self.assertEqual(yml, expected, "unexpected parse result")
