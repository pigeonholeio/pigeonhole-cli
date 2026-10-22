# PigeonHole CLI

PigeonHole CLI is the modern way to send secrets, files, or any text securely. Encrypt and share sensitive information using end-to-end encryption with support for multiple recipients.

## Features

- 🔐 **End-to-End Encryption (E2EE)** - Military-grade encryption using GPG
- 👥 **Multi-Recipient Support** - Share with multiple people securely
- 📁 **File & Text Sharing** - Send files or text securely
- 🔑 **GPG-Based Key Management** - Full control over your encryption keys
- 🌐 **OIDC Authentication** - Authenticate with your identity provider
- ✨ **Modern CLI Experience** - User-friendly command-line interface

## Getting Started
Head over to the [Quick Start Guide](https://pigeono.io/quick-start/) on how to install and send your first secret!


### Common Commands (v1 — Cloudflare backend, api.pigeono.io)

- `pigeonhole login --email you@example.com` - Create your device keypair and enrol
- `pigeonhole send --to someone@example.com [file]` - Encrypt (OpenPGP) and send a secret (file or stdin)
- `pigeonhole send --to a@x.com --onetime -` - Burn-after-read from stdin
- `pigeonhole list` - List your available secrets
- `pigeonhole receive --ref <reference>` - Download and decrypt (to stdout, or `-o file`)

> **v1 note:** v1.0.0 is a ground-up rebuild on Cloudflare (Workers/R2/D1) with a
> keypair identity and end-to-end OpenPGP encryption. Keys are generated locally and
> never leave your device (losing your key = losing access, by design). Legacy
> commands from 0.x have been retired pending reimplementation on the new backend.

## Configuration

Configuration files are stored in:

**Windows**: `%APPDATA%\.pigeonhole\config.yaml`
**macOS/Linux**: `~/.pigeonhole/config.yaml`

## Documentation

- 📖 **Full Documentation**: https://pigeono.io
- 🆘 **Troubleshooting**: https://pigeono.io/docs/troubleshooting

## Support

- 🐛 **Bug Reports**: https://github.com/pigeonholeio/pigeonhole-cli/issues
- 💬 **Discussions**: https://github.com/pigeonholeio/pigeonhole-cli/discussions
- 📧 **Email**: support@pigeono.io
- 🐦 **Twitter**: [@pigeonholeio](https://x.com/pigeonholeio)

## License

see [LICENSE](./LICENSE) for details

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

**Built with ❤️ by the PigeonHole Team**