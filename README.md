# zerotunnel

Secure P2P file transfer tool.

zerotunnel uses the KAPPA protocol to establish ephemeral session keys using a PQ-hardened cryptographic handshake. Read the KAPPA specification (WIP) [here](docs/specifications/KAPPA.md).

## Directions to install

```bash
git clone https://github.com/vibhav950/zerotunnel.git
cd zerotunnel
mkdir build && cd build
cmake ..
make
```

## TODO

- [ ] Add multi-file transfer ([multio-dev branch](https://github.com/vibhav950/zerotunnel/tree/multio-dev)).
- [ ] Add recursive directory iteration.
- [ ] Decouple the client/server and TCP connection utils.
