# Py225 (PyProject 2025)

## Description
Python web tunneling program that supports TCP and UDP.


Principle:

1. Client authenticates to server and queries session on start up.
2. Server verifies client's identity, then provides random ports for client to connect to and session expire time.
3. Client closes query connection when it's done.
4. When application connects to client, client establishes encrypted data link to one of the provided ports.
5. Server receives data link, and connects to target predefined in config file.
6. TCP tunnel between application and the target is then established.
7. Client queries session again when session is expired.

UDP works basically the same.

## Features
- Uses Ed25519 keys, X25519 key exchange and ChaCha20-Poly1305 encryption to enhance security
- Random ports on server side
- No handshake during establishment of data link between client and server, meaning 0 RTT cost
  - Info required for establishment is obtained from session query at the very beginning
  - Congestion window is applied to make sure nonce used in each data link is different.
- Supports stderr, file, Syslog and NT Event Log logging

## Usage
Config file is mandatory, see section below.
```shell
python src/py225.py # Client side
py225 # Client side, if binary is built and in PATH

python src/py225d.py # Server side
py225d # Server side, if binary is built and in PATH
```
Cmdline args:
```text
usage: py225d [-h] [-c CONFIG] [-v [VERBOSE]] [-l LOG]

PyProject 2025

options:
  -h, --help            show this help message and exit
  -c, --config CONFIG
  -v, --verbose [VERBOSE]
  -l, --log LOG
```
### Config
Config is required to run `py225` and `py225d`.

Config file name: 
```text
# Client
py225.yaml
py225.yml

# Server
py225d.yaml
py225d.yml
```

Default config folders (Linux):
- `$XDG_DATA_HOME/py225/`
- `~/.local/share/py225/`
- `/etc/`
- Working directory
- Parent folder of the running script or binary

Default config folders (Windows):
- `%LocalAppData%\py225\`
- Working directory
- Parent folder of the running script or binary

Default config folders (Other platforms):
- Working directory
- Parent folder of the running script or binary

Example config paths:
```text
# Server config on Linux systems
/etc/py225d.yml

# Client config on Windows
C:\Users\Administrator\AppData\Local\py225\py225.yml

# Client config on Linux
~/.local/share/py225/py225.yaml
```

#### Example config for client
```yaml
!Client # This line is mandatory
listen_ip: 127.0.0.1 # Listen address for application to connect to client
listen_port: 1080

log: stderr # Supported: file path, stderr, syslog, nt. Detected automatically if absent.

# Default private key.
private_key: '-----BEGIN PRIVATE KEY-----

  **private key here**

  -----END PRIVATE KEY-----'
servers: # Currently only 1 server is supported.
- !ServerRecord
  host: google.com
  # Optional, but strongly recommended.
  host_public_key: '-----BEGIN PUBLIC KEY-----

    **public key here**

    -----END PRIVATE KEY-----'
  port: 443
- !ServerRecord
  host: cloudflare.com
  host_public_key: null
  port: 888
  # Private key specifically for this server.
  private_key: '-----BEGIN PRIVATE KEY-----

    **private key here**

    -----END PRIVATE KEY-----'
verbosity: warning
```
#### Example config for server
```yaml
!Server
listen_ip: 0.0.0.0

# Range of random ports (for TCP and UDP data links)
listen_port_range: [40000, 45000]
# Ports are selected from above range.
percent_of_open_ports_range: [30%, 50%]
# How long the ports last and get chosen again.
ports_lasting_duration_mins_range: [600, 1200]
# In this instance, 30%~50% of ports among 40000 and 45000 are selected,
# they last 600~1200 minutes, after that another random set of ports are selected again.

# Port for client to query session info.
serv_win_port: 1888
# How long the session lasts.
serv_win_duration_mins_range: [60, 120]
# In this instance, client connects to port 1888 to query session info.
# Session lasts 60~120 minutes.

# Target address.
connect_host: 127.0.0.1
connect_port: 3000

log: syslog # Supported: file path, stderr, syslog, nt. Detected automatically if absent.
verbosity: info

private_key: '-----BEGIN PRIVATE KEY-----

  **private key here**

  -----END PRIVATE KEY-----'

# Allowed client public keys
accepted_keys: 
- '-----BEGIN PUBLIC KEY-----

  **client public key here**

  -----END PUBLIC KEY-----'
- '-----BEGIN PUBLIC KEY-----

  **client public key here**

  -----END PUBLIC KEY-----'
- '-----BEGIN PUBLIC KEY-----

  **client public key here**

  -----END PUBLIC KEY-----'
```

## Build binaries
Build binaries if you want.  
Docker is suggested for compatibility among different Linux distributions.
### PyInstaller
```shell
pyinstaller --onefile src/py225.py
pyinstaller --onefile src/py225d.py
```
Binaries are under `./dist/`
### Docker (Linux executables)
```shell
docker build . -t container-name
docker run container-name
docker cp container-name:/opt/py225/dist-onefile .
```
Binaries are under `./dist-onefile/`. Container is removable after build.