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


### Common Commands

- `pigeonhole auth login` - Authenticate with your identity provider
- `pigeonhole auth list-providers` - List available identity providers
- `pigeonhole keys init` - Initialize GPG key pair
- `pigeonhole secret send` - Send a secret securely
- `pigeonhole secret list` - List received secrets
- `pigeonhole secret receive` - Receive and decrypt a secret

## Configuration

Configuration files are stored in:

**Windows**: `%APPDATA%\.pigeonhole\config.yaml`
**macOS/Linux**: `~/.pigeonhole/config.yaml`

## Documentation

- 📖 **Full Documentation**: https://pigeono.io
- 🆘 **Troubleshooting**: https://pigeono.io/docs/troubleshooting
- 🪟 **Windows-Specific**: [Chocolatey Guide](./docs/CHOCOLATEY.md)

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