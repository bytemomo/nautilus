# Kraken

Kraken is a security testing tools used in networking, it is developed to be as
easy as possible for the user to extend it, as such is very simple and the codebase
is as small as possible.

Its functionality is to orchestrate security testing against some targets (e.g
ip targets). The security testing is implemented under the name of module.

## Modules

A module can be of three types:

1. GRPC: a type of distributed module, in the configuration file it is specified
   the \<host\>:\<port\> of the plugin. When the plugin is required to run against a
   target the orchestrator will connect to the specified server and run the test.
2. CLI: a type of local module, it is runned as a stand alone process by the orchestrator
   and it must comply to a specific cli interface. Also it should report results
   in a standard format.
3. LIB: a type of local module, it is loaded at runtime, the orchestrator will
   search for symbols in the provided lib(s)

## LIB Modules

The lib modules can be implemented with two APIs:

- The v1 ABI will require the module to handle everything, also the transport
  settings. If the module needs to use TLS then with this API the module developer
  needs to handle itself.
- The v2 ABI will instead lift the ownership of the transport implementation from
  the developer, infact with the v2 there are some standard transports that
  can be used by the plugin (the used transport needs to be specified in the
  configuration file). There are some limitations such as this type of plugin
  can not enstablish multiple connections in one session therefore attacks
  such as a dictionary attack can not be implemented.

## CLI Modules

The cli modules have only one version of API, they take the target as input and
run the test against it.

> Being on the same machine the CLI module can always reach the target found by
> Kraken.

## GRPC Modules

The lib modules have only one version of API, they take the target as input and
run the test against it.

> The ABI module, being distributed, could be on a different machine. The developer
> should assert that a certain target can be reached from the machine the module
> is installed over.
