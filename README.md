# Talk

**Prototype. Not audited. Do not use it for real conversations, and never where your safety depends on it.**

Talk is an end-to-end encrypted group messenger built on the Messaging Layer Security standard (MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)). It uses hybrid classical and post-quantum key exchange: X25519 combined with ML-KEM-768, through the X-Wing construction.

## Status

- The core passes 57 automated security and reliability tests on macOS and Linux. They cover tampering with every byte, replay, impersonation and forged certificates.
- The relay uses TLS 1.3 with hybrid X25519MLKEM768 key exchange and client certificates.
- Local data is kept in an Argon2id-encrypted vault.
- Identities are checked with 40-digit safety codes.
- There is a desktop test app for Mac, built with Tauri 2. An iPhone/iPad build has run in the simulator only.

## Known limits

- **No independent security review yet.** An audit is planned. Until its findings are fixed, Talk must not be used by people at risk.
- Authentication still uses classical signatures. Only key exchange is post-quantum.
- The post-quantum MLS cipher suites are drafts and may change. Library versions are pinned exactly for that reason.
- No device revocation, account recovery or abuse reporting yet.
- The two-device link in the desktop app is a private test feature tied to one test machine. It is not a general networking feature.
- The full list of limits is in [REPORT.md](REPORT.md).

## Building

You need Rust (stable).

```bash
cargo test
```

The desktop app is in `app/`. It needs Node.js for the Tauri CLI:

```bash
cd app && npm install && npx tauri build
```

## How it was built

The code was written by the founder of Topologixlabs Ltd with AI coding tools, under close review and extensive automated testing. We say this openly so reviewers can weigh it.

## Reporting security problems

Please email info@topologixlabs.com rather than opening a public issue. Please use only fictional data when testing.

## Licence

Copyright (C) 2026 Topologixlabs Ltd.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License, version 3, as published by the Free Software Foundation. See [LICENSE](LICENSE).

Talk builds on [OpenMLS](https://github.com/openmls/openmls), [libcrux](https://github.com/cryspen/libcrux), [rustls](https://github.com/rustls/rustls) and other open-source libraries, each under its own licence.
