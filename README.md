# Nautilus

Nautilus is a software suite which containes two executables: _kraken_ and _siren_,
this applications are used to tests network protocols and targets in the IoT
environment.

The main requirements with which these applications where developed is _modularity_.

The two agents do complementary jobs on network environments:

- **kraken** tests servers acting as a client that can execute modules that implements
  security testing. A module can implement fuzzing, specific CVE, misconfiguration
  checks, etc...
- **siren** tests clients by transparently intercepting traffic directly in the
  kernel via eBPF/XDP/TC. The agent attaches to an interface and copies packets
  that match the configured `targets` (IP, `ip:port`, MAC, or EtherCAT slave ID),
  keeping deployment simple while remaining invisible to endpoints. Siren's
  intercept engine exposes the same manipulation capabilities:
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

Other than the two agents the suite include a small and simple library called
**trident** that abstract away networking primitives to open connections, intruducing
the concept of `conduit`. The idea is to have an abstraction that expose 5 methods:
dial, close, kind, stack and underlying. The main methods is the underlying one
that returns the underlying layer-specific interface for performing I/O actions.
With this abstraction kraken and siren are developed. This gives the advantage
of not bothering with transport specific logic and use them as black boxes.

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
├── siren               // Siren eBPF MITM
│   ├── config
│   ├── config.yaml
│   ├── ebpf
│   │   └── program
│   ├── go.mod
│   ├── go.sum
│   ├── intercept
│   ├── main.go
│   ├── pkg
│   ├── proxy
│   └── recorder
└── trident             // Trident library (used to abstract transports)
    ├── conduit
    ├── go.mod
    └── go.sum
```

## Documentation

### Project specific documentation

- [Kraken docs](docs/kraken/documentation.md) --- Campaign orchestration, module APIs, attack trees, and usage.
- [Trident docs](docs/trident/documentation.md) --- Transport abstraction and conduit system.
- [Siren docs](docs/siren/documentation.md) --- Man-in-the-Middle for client testing

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

### trident

Trident library has tests for each underlying type of conduit, the test for tcp,
tls, udp and dtls can be run as user.

To run the tests simply execute the following:

```sh
go test ./trident/...
```

The tests for the network and ip layer needs `sudo` or at least `cap_net_raw`
and `cap_net_admin+ep` permissions.

### kraken

As with **trident** the tests for kraken can be run with the following:

```go
go test ./kraken/...
```

> [!WARNING]
> The problem with kraken tests is that they are not nearly as completed.
> Also kraken is missing integration tests.

### siren

Siren relies on an eBPF program that is pre-built inside the repository. If you
change `siren/ebpf/program/xdp_proxy.c`, regenerate the object with `go generate`
and then run:

```sh
go generate ./siren/ebpf
go build ./siren
sudo ./siren -config siren/config/example-ebpf.yaml
```

Recording produces PCAP files by default so you can open captures in
Wireshark immediately. Attaching the XDP hook requires root or the relevant
capabilities, and you must pass the interface name via the configuration
(`ebpf.interface`).

The optional `targets` list accepts strings such as:

- `"ip:192.0.2.10"`
- `"ip_port:192.0.2.10:1883"`
- `"mac:aa:bb:cc:dd:ee:ff"`
- `"ethercat:0x1234"`

Leaving the list empty captures everything on the interface.

## Deploy

The deployment scripts are inside the `deploy/` folder, both _kraken_ and _siren_
are conteinerized using Docker. Other than the two agents there can be found some
examples of network environments to run the two agents.

Naturally the environments reproduced are an abstraction of what a real environment
would be. This environments are used to showcase the two agents and the relative
modules.

As _siren_ is still in development the majority of deployment environments is for
_kraken_.

For other information look at the ![readme](./deploy/README.md) inside the deloy
folder. There, all the commands to build and run the agents and environments can be
found.

> [!NOTE]
> Just as a note all the servers (or brokers) that have been tested and reproduced
> via Docker are build with instrumentation **on** to potentially catch interesting
> bugs while **fuzzing**.

## TODO

### General

- [ ] Module that checks a selection of particularly interesting properties of MQTT

### Scenarios

- [ ] Create simple mqtt scenario to test the agents, should have:
    - [ ] MQTT Broker (interchangeable: Mosquitto, Emqx, Nanomq)
    - [ ] Use clients like (mosquitto_sub and mosquitto_pub) to simulate traffic
- [ ] Create simple RTSP scenario to test the agents
- [ ] Create a simple Purdue example
    - First network (operational)
        - [ ] 2 Broker MQTT that talks with other devices (1 weak and 1 strong)
        - [ ] Device that have weak creds
        - [ ] Device that have weak ssh
        - [ ] Device that have weak telnet
        - [ ] Device that have multiple vulns
        - [ ] Device that is secure
    - Second network (it)
        - [ ] RTSP camera (fake)
        - [ ] RTSP server (weak conf)
- [ ] Fuzzing scenario, this is different as the targets can be pre-defined and
      can be accessed with more ease. We don't have only black box analysis (boofuzz)
      but also a gray/white box one (AFL++).
    - Multiple brokers
        - [ ] Mosquitto
        - [ ] Emqx
        - [ ] Nanomq
    - Clients
        - [ ] mosquitto_sub
        - [ ] mosquitto_pub

### Fuzzing

#### Black box

Black box fuzzing work by interacting in the legit way with the server/broker.
Boofuzz, grammar based, is an implementation

- [x] Black box fuzzing module for MQTT
    - [x] Boofuzz - grammarbased
- [ ] Black box fuzzing module for RTSP
    - [x] Boofuzz - grammarbased

#### Gray box

Gray box fuzzing work by interacting with the SUT using harnesses, the major exponent
is AFL++, to run this against the target the source code has to be available and
has to be recompiled (AFL++ can be run also using qemu but this is out of scope).

- [ ] Gray box fuzzing module for MQTT
    - [ ] AFL++ - mutation based
- [ ] Gray box fuzzing module for RTSP
    - [ ] AFL++ - mutation based

#### White box

White-box fuzzing, also known as source-code fuzzing or clear-box fuzzing,
involves full knowledge of the program's internal structure and code. It is often
implemented using dynamic symbolic execution (DSE) or concolic execution, which
systematically explore program paths by solving mathematical constraints on inputs
to force the program to take different branches
