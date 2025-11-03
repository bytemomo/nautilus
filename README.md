# Nautilus

Nautilus is a modular framework for security assessment and automation in IoT and embedded systems. It provides a scalable, extensible platform for orchestrating security campaigns, protocol testing, transport abstraction, and reporting.

## Project Structure

Nautilus is composed of several subprojects, each with a distinct role:

- **kraken/**
  The main orchestrator for security campaigns. Handles scanning, classification, module execution, and reporting.
  See [`kraken/README.md`](kraken/README.md) for details.

- **trident/**
  Transport abstraction layer. Implements conduits for stream and datagram protocols (TCP, TLS, UDP, DTLS, etc.), used by Kraken and modules.

- **siren/**
  Man-in-the-Middle testing proxy for client validation. Intercepts, modifies, delays, or drops traffic to test client resilience.
  See [`siren/README.md`](siren/README.md) for details.

- **campaigns/**
  Example and template campaign definitions (YAML files) for various IoT protocols and scenarios.

- **modules/**
  Directory for custom security test modules (modules) in ABI, CLI, or gRPC formats.

- **results/**
  Output directory for generated reports and findings.

## Getting Started

1. **Clone the repository**

    ```sh
    git clone https://github.com/your-org/nautilus.git
    cd nautilus
    ```

2. **Build Kraken**

    ```sh
    cd kraken
    go build -o kraken main.go
    ```

3. **Run a campaign**
    ```sh
    ./kraken -campaign ../campaigns/example.yaml -cidrs "192.168.1.0/24" -out ../results
    ```

## Documentation

- [Kraken README](kraken/README.md) — Campaign orchestration, module APIs, attack trees, and usage.
- [Trident README](trident/README.md) — Transport abstraction and conduit system.
- [Siren README](siren/README.md) — Man-in-the-Middle proxy for client testing and fault injection.

## Roadmap

- Expand protocol support
- Distributed and cloud-based execution
- Advanced reporting and visualization
