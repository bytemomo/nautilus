# Nautilus

Nautilus is a software suite which containes two executables: _kraken_ and _siren_,
this applications are used to tests network protocols and targets in the IoT
environment.

The main requirements with which these applications where developed is _modularity_.

The two agents do complementary jobs on network environments:

- **kraken** tests servers acting as a client that can execute modules that implements
  security testing. A module can implement fuzzing, specific CVE, misconfiguration
  checks, etc...
- **siren** tests clients acting as a transparent proxy in-between the real server
  and client. This gives great flexibility as the proxy can simply forward the messages
  to the server and get what would be the real response, also being transparent
  gives an advantage to modify as little as possible the environment configuration.
  Siren main objective is to be able to interact and tests clients as such it can:
    1. Modify traffic
    2. Delay traffic
    3. Rule based approaches on traffic (regex)
    4. Log traffic
    5. Drop traffic
    6. Duplicate traffic
    7. Throttle traffic
    8. Corrupting traffic ()
    9. Module based interaction: instead of the connection handle, siren, will
       forward the data already parsed based on a user-defined schema in YAML/source.

> [!NOTE]
> Having limited time the siren implementation is not finished and not polished
> as i would like it to be.
>
> It would be nice if siren could use eBPF as such it would be completely transparent.
> could be load on the machine the server is located and simply intercept everything
> from the kernel space, reducing the delay and having a simpler testing deployment
> on the environment.

Other than the two agents the suite include a small and simple library called
**trident** that abstract away networking primitives to open connections, intruducing
the concept of `conduit`. The idea is to have an abstraction that expose 5 methods:
dial, close, kind, stack and underlying. The main methods is the underlying one
that returns the underlying layer-specific interface for performing I/O actions.
With this abstraction kraken and siren are developed. This gives the advantage
of now bothering with transport specific logic and use them as black boxes.

```go
// Conduit is the core abstraction in Trident, representing a connection or socket
// at a specific network layer. Conduits are composable, allowing for the creation
// of protocol stacks (e.g., TLS over TCP).
// The generic type V specifies the underlying layer-specific interface (e.g., Stream, Datagram).
type Conduit[V any] interface {
	// Dial establishes the connection or prepares the socket for use.
	// It is idempotent; subsequent calls should have no effect.
	Dial(ctx context.Context) error
	// Close tears down the connection and releases all associated resources.
	Close() error

	// Kind returns the operational layer of the conduit.
	Kind() Kind
	// Stack returns a slice of strings representing the protocol stack,
	// from the outermost layer to the innermost (e.g., ["tls", "tcp"]).
	Stack() []string

	// Underlying returns the layer-specific interface for performing I/O.
	// For example, a TCP conduit would return an implementation of the Stream interface.
	Underlying() V
}
```

## Project Structure

```text
.
├── campaigns           // Contains standard campaigns for kraken
│   ├── iot-fuzzing.yaml
│   ├── iot-standard.yaml
│   ├── README.md
│   └── trees
├── docs
│   ├── kraken
│   ├── siren
│   └── trident
├── go.work
├── go.work.sum
├── Justfile
├── kraken              // kraken source code
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   ├── main.go
│   └── pkg
├── modules             // Contains modules used by kraken and siren
│   ├── kraken
│   └── siren
├── README.md
├── kraken-results      // Here will be placed the results of the kraken-campaigns
│   ├── iot-standard
│   └── kraken.log
├── siren               // PoC of siren MiTM transparent proxy
│   ├── config
│   ├── go.mod
│   ├── go.sum
│   ├── intercept
│   ├── main.go
│   ├── proxy
│   ├── recorder
│   ├── scenarios
│   ├── scripts
│   └── spoof
└── trident             // Trident library (used to abstract transports)
    ├── conduit
    ├── go.mod
    └── go.sum
```

## Documentation

### Project specific documentation

- [Kraken docs](docs/kraken/documentation.md) --- Campaign orchestration, module APIs, attack trees, and usage.
- [Trident docs](docs/trident/documentation.md) --- Transport abstraction and conduit system.
- [Siren docs](docs/siren/documentation.md) --- Man-in-the-Middle proxy for client testing and fault injection.

### Code specific documentation

Go code is documented using ![`godoc`](https://go.dev/blog/godoc), to generate the
source documentation this tool has to be used.

To install and learn how to use it go to the official documentation or at this
![example page](https://github.com/amalmadhu06/godoc-example).

> [!NOTE]
> The packages were implemented using the core concepts of golang in mind, as such
> the code that is not accessed externally from the package is put inside the
> interal folder. Godoc will not make the documentation of that code visible, to
> access it the tag `?m=all` has to be used as query in the godoc local website.

## Module based documentation

Modules can be written in various languages and so they use their specific tools
for generating documentation, the one used for `C/C++` is deoxygen and the one used
for `rust` is rustdoc.

The way to generate this type of documentation is leaved to the user of the module.

What modules MUST provide is instead a high-level description of what the module
does, the permissions required, and also a warning if it can create distruption.
This type of documentation will be provided as a `README.md` inside the specific
module folder.

## Testing

Ideally each agents has integrations and unit testing.

## trident

Trident library has tests for each underlying type of conduit, the test for tcp,
tls, udp and dtls can be run as user.

To run the tests simply execute the following:

```sh
go test ./trident/...
```

The tests for the network and ip layer needs `sudo` or at least `cap_net_raw`
and `cap_net_admin+ep` permissions. For now these tests are done manually, the
future idea, to make everything more easy and smooth to use is to run them in
a safe environment like an isolated namespace or a container with the right
capabilities.

## kraken

As with **trident** the tests for kraken can be run with the following:

```go
go test ./kraken/...
```

> [!WARNING]
> The problem with kraken tests is that they are not nearly as completed.
> Also kraken should

## siren

% TODO
