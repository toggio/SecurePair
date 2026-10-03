# Security

SecurePair is beta software, and its protocol has not been reviewed by an independent cryptographer yet. [docs/PROTOCOL.md](docs/PROTOCOL.md) describes the protocol, the threat model and the known limits.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use *Security > Report a vulnerability* on the GitHub repository, which keeps the report private, and include:

- the version or commit;
- what an attacker can do, and under which conditions;
- a way to reproduce it, if you have one. The host tests in `extras/test` are a good place to start.

Fixes are published in a new release, with credit to the reporter unless they prefer otherwise.

## Supported versions

Only the latest release is maintained.
