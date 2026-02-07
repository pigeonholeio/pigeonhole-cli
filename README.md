# PigeonHole CLI

PigeonHole CLI is the modern way to send secrets, files, or any text securely. Encrypt and share sensitive information using end-to-end encryption with support for multiple recipients.

## Features

- 🔐 **End-to-End Encryption (E2EE)** - Military-grade encryption using GPG
- 👥 **Multi-Recipient Support** - Share with multiple people securely
- 📁 **File & Text Sharing** - Send files or text securely
- 🔑 **GPG-Based Key Management** - Full control over your encryption keys
- 🌐 **OIDC Authentication** - Authenticate with your identity provider
- ✨ **Modern CLI Experience** - User-friendly command-line interface

## Installation

### Windows (Chocolatey)

```powershell
choco install pigeonhole-cli --source https://packages.pigeono.io/choco/
```

Once approved in the Chocolatey community repository:
```powershell
choco install pigeonhole-cli
```

For more details, see [Chocolatey Installation Guide](./docs/CHOCOLATEY.md).

### macOS (Homebrew)

```bash
brew install pigeonholeio/pigeonhole/pigeonhole-cli
```

### Linux (DEB packages)

```bash
# Ubuntu/Debian
curl -fsSL https://packages.pigeono.io/gpg.pub | sudo apt-key add -
echo "deb https://packages.pigeono.io/apt noble main" | sudo tee /etc/apt/sources.list.d/pigeono.list
sudo apt update
sudo apt install pigeonhole-cli
```

### Linux (RPM packages)

```bash
# RedHat/Fedora/CentOS
sudo rpm --import https://packages.pigeono.io/gpg.pub
sudo dnf install -y 'dnf-command(config-manager)'
sudo dnf config-manager --add-repo https://packages.pigeono.io/rpm
sudo dnf install pigeonhole-cli
```

### From Source

```bash
cd src
go build -o pigeonhole ./main.go
```

## Quick Start

### 1. Authenticate

```bash
pigeonhole auth login
```

This starts the OAuth2 device authorization flow. Follow the prompts to authenticate with your identity provider.

### 2. Set Up Encryption Keys

```bash
pigeonhole keys init
```

This creates a GPG key pair for end-to-end encryption.

### 3. Send a Secret

```bash
pigeonhole secret send -r recipient@example.com -f myfile.txt
```

Or send text:
```bash
pigeonhole secret send -r recipient@example.com -t "My secret message"
```

### 4. View Secrets

```bash
pigeonhole secret list
```

## Usage

View all available commands:

```bash
pigeonhole --help
```

Get help for a specific command:

```bash
pigeonhole <command> --help
```

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

MIT License - see [LICENSE](./LICENSE) for details

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

**Built with ❤️ by the PigeonHole Team**