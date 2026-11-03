# Docker

## GHCR

Container images are published to GitHub Container Registry:

```sh
docker pull ghcr.io/vovvan/byedpi:latest
```

Images are built for `linux/amd64` and `linux/arm64`. Branch builds use the
branch name as a tag, release tags use the version tag, and the default branch
also updates `latest`.

## Building

```sh
docker build . --tag byedpi
```

Provided `Dockerfile` is compatible with podman as well.

## Running

```sh
docker run -it --rm -p 127.0.0.1:1080:1080 ghcr.io/vovvan/byedpi:latest --help
```

To expose the SOCKS proxy only on the local machine:

```sh
docker run -d --name byedpi --restart unless-stopped \
  -p 127.0.0.1:1080:1080 \
  ghcr.io/vovvan/byedpi:latest --tlsrec 1+s --disorder 1+s
```

Then configure the browser to use SOCKS5 `127.0.0.1:1080`.

The default command already enables the Go version's tested YouTube profile.
Arguments after the image name replace the default command.

### UDP and QUIC

SOCKS5 UDP ASSOCIATE uses an ephemeral UDP port, so publishing `1080/udp` is
not enough for UDP traffic. Use host networking if you need UDP associate:

```sh
docker run --network host ghcr.io/vovvan/byedpi:latest
```

Browsers still do not send QUIC through SOCKS5 UDP ASSOCIATE; for QUIC use a
TUN/TPROXY or a QUIC-capable tunnel instead.

## Compose

Edit arguments in `command` and the published port in `compose.yaml`, then run:

```sh
docker compose up -d
```

If the Docker daemon starts on system boot, the container will stay up.
