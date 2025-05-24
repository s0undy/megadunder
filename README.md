# megadunder

Saker som kan vara bra att ha ツ

> Garanterar inte 100% korrekt funktion, använd på egen risk ¯\\\_(ツ)\_/¯

## Features

### Network Tools
- IPv4 and IPv6 support
- Multiple network tools:
  - ping
  - curl (with HTTP/HTTPS support)
  - telnet
  - traceroute

### DNS Tools
- Support for common record types:
  - A, AAAA (IPv4/IPv6 addresses)
  - CNAME (Canonical Name)
  - MX (Mail Exchange)
  - TXT (Text Records)
  - NS (Name Server)
  - SOA (Start of Authority)
  - PTR (Pointer Records)
- DNSSEC support:
  - DNSKEY (DNSSEC Public Key)
  - DS (Delegation Signer)
  - RRSIG (Resource Record Signature)
  - NSEC/NSEC3 (Next Secure Records)
- Automatic PTR record formatting
- DNSSEC validation status

### Certificate Tools
- SSL/TLS certificate inspection
- Full certificate chain validation
- Revocation status checking (CRL/OCSP)
- Visual certificate chain display
- Expiry warnings and notifications
- Detailed certificate information

### Mail Tools
- Comprehensive email server configuration checks:
  - SPF (Sender Policy Framework) validation
  - DMARC policy verification
  - DKIM record checking
  - MX record validation
  - SMTP server testing
- TLS support verification
- Detailed reporting and recommendations

### UI Features
- Modern, responsive web interface with Tailwind CSS
- Dark mode support
- Real-time validation
- Interactive visualizations
- Detailed error handling and feedback

## Getting Started

### Running with Docker

#### Using Docker Compose (Recommended)

1. Create a `docker-compose.yml` file:
```yaml
version: '3.8'

services:
  megadunder:
    image: ghcr.io/s0undy/megadunder:0.1.1
    container_name: megadunder
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - TZ=UTC
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

2. Start the container:
```bash
docker compose up -d
```

3. Access the application at http://localhost:8080

#### Building and Running with Docker

1. Clone the repository:
```bash
git clone https://github.com/s0undy/megadunder.git
cd megadunder
```

2. Build the Docker image:
```bash
docker build -t megadunder .
```

3. Run the container:
```bash
docker run -d \
  --name megadunder \
  -p 8080:8080 \
  --restart unless-stopped \
  megadunder
```

4. Access the application at http://localhost:8080

### Manual Installation

### Prerequisites

#### Software Requirements
- Go 1.24.3 or higher
- A modern web browser with JavaScript support

#### System Commands
The following commands must be available in your system's PATH:
- `ping` and `ping6` for IPv4/IPv6 ping tests
- `curl` for HTTP/HTTPS requests
- `telnet` for telnet connections
- `traceroute` and `traceroute6` for network route tracing
- `timeout` for command execution control
- `dig` for DNS lookups
- `openssl` for certificate operations

On Ubuntu/Debian systems, you can install these with:
```bash
sudo apt-get update
sudo apt-get install iputils-ping traceroute curl telnet dnsutils openssl
```

On CentOS/RHEL systems:
```bash
sudo yum install iputils traceroute curl telnet bind-utils openssl
```

### Building

```bash
go build
```

### Running

```bash
./megadunder
```

Then open your browser to http://localhost:8080

## License

This project is licensed under the MIT License - see the LICENSE file for details. 