# Docker & Kubernetes Certificate Automation

![License](https://img.shields.io/github/license/davestj/docker-k8s-cert-automation)
![GitHub last commit](https://img.shields.io/github/last-commit/davestj/docker-k8s-cert-automation)

Automated certificate management solution for Docker Desktop and Kubernetes environments, providing seamless SSL/TLS certificate generation and distribution for local development.

## Features

- 🔐 Automated self-signed certificate generation using Certbot
- 🐳 Automatic certificate distribution to Docker containers
- ⎈ Kubernetes integration for pod certificate management
- 🔄 Scheduled certificate renewal and distribution
- 🚀 Zero-touch deployment for local development
- 📦 Multi-domain support
- 🔌 Hot-reload support for services

## Prerequisites

- Docker Desktop with Kubernetes enabled
- Git
- Python 3.13 (installed via Homebrew)
- Docker Desktop 27.5.1 or later

## Quick Start

1. Clone the repository:
```bash
git clone git@github.com:davestj/docker-k8s-cert-automation.git
cd docker-k8s-cert-automation
```

2. Create required directories:
```bash
mkdir -p data/certbot/conf data/certbot/www
```

3. Build and start services:
```bash
docker-compose build
docker-compose up -d
```

4. Deploy to Kubernetes:
```bash
kubectl create namespace cert-manager
kubectl apply -f k8s-deployment.yaml
```

## Usage

### Docker Container Configuration

Add these labels to your Docker containers to enable automatic certificate management:

```yaml
services:
  your-service:
    labels:
      - "ENABLE_SSL=true"
      - "CERT_DOMAIN=localhost"
      - "RELOAD_CMD=nginx -s reload"  # Optional, for service reload
```

### Kubernetes Configuration

Certificates are automatically created as Kubernetes secrets. Use them in your deployments:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  tls:
    - hosts:
        - localhost
      secretName: tls-localhost
```

## Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| CERT_RENEWAL_INTERVAL | 12h | Certificate check/update interval |
| CERT_PATH | /etc/letsencrypt/live | Certificate storage location |

## Project Structure

```
.
├── docker-compose.yml           # Main compose file
├── Dockerfile.cert-manager      # Cert manager image definition
├── cert-manager.py             # Core certificate management logic
├── requirements.txt            # Python dependencies
├── k8s-deployment.yaml         # Kubernetes deployment config
└── data/                       # Certificate storage
    ├── certbot/
    │   ├── conf/              # Certbot configuration
    │   └── www/               # Webroot for challenges
    └── README.md
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/davestj/docker-k8s-cert-automation/issues/new) on GitHub.
