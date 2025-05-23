# megadunder

A collection of network tools written in Go.

## Features

- IPv4 and IPv6 support
- Multiple network tools:
  - ping
  - curl (with HTTP/HTTPS support)
  - telnet
  - traceroute
- DNS lookup tools:
  - Support for common record types (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR)
  - Clean, formatted output
  - Automatic PTR record formatting
- Modern web interface with Tailwind CSS
- Command timeouts for safety
- Detailed error handling

## Getting Started

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

On Ubuntu/Debian systems, you can install these with:
```bash
sudo apt-get update
sudo apt-get install iputils-ping traceroute curl telnet dnsutils
```

On CentOS/RHEL systems:
```bash
sudo yum install iputils traceroute curl telnet bind-utils
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