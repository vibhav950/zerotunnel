# zerotunnel

Secure P2P file transfer tool.

zerotunnel uses the KAPPA protocol to establish ephemeral session keys using a PQ-hardened cryptographic handshake. Read the KAPPA specification (WIP) [here](docs/specifications/KAPPA.md).

## TODO

- [X] Complete the crypto API.
- [X] Add support for LZ4 compression.
- [X] Add signal handlers to cleanup on Ctrl-C, etc.
- [X] Write the net utils (client and server state machines).
- [X] Add options parser.
- [ ] Write tests for all crypto modules.
- [X] Implement ciphersuites and ciphersuite negotiation.
- [ ] Add support for sending multiple files and entire folders.
- [ ] Add the ability to read the input file from stdin.
- [ ] Multi-threaded file read/send.
