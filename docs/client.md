# Client

## Building the Client

To build the latest keyholder binaries from master, simply invoke the Go toolchain like so:

```
$ export GO111MODULE=on
$ go get -v github.com/inconsiderable/pass-thread/client
$ go install -v github.com/inconsiderable/pass-thread/client
```

The passthread bins should now be available in your go-managed `$GOPATH/bin` (which is hopefully also on your `$PATH`). You can test this by running `client -h` to print the help screen.

## CLI Options

Client help is available via the `client -h` command:

```
$ client -h
Usage of /home/passthread/go/bin/client:
  -compress
        Compress passes on disk with lz4
  -datadir string
        Path to a directory to save pass thread data
  -dnsseed
        Run a DNS server to allow others to find peers
  -inlimit int
        Limit for the number of inbound peer connections. (default 128)
  -keyfile string
        Path to a file containing public keys to use when weaving
  -memo string
        A memo to include in newly weaved passes
  -noaccept
        Disable inbound peer connections
  -noirc
        Disable use of IRC for peer discovery
  -numweavers int
        Number of weavers to run (default 1)
  -peer string
        Address of a peer to connect to
  -port int
        Port to listen for incoming peer connections (default 8832)
  -prune
        Prune consideration and public key consideration indices
  -pubkey string
        A public key which receives newly weaved pass points
  -tlscert string
        Path to a file containing a PEM-encoded X.509 certificate to use with TLS
  -tlskey string
        Path to a file containing a PEM-encoded private key to use with TLS
  -upnp
        Attempt to forward the passthread port on your router with UPnP
```

## Running the Client

The client requires a data dir for storage of the pass-thread and general metadata as well as one or more public keys to send pass points to upon weaving. Otherwise, running the client is as simple as:

```
$ client -datadir pass-data -keyfile keys.txt -numweavers 2
```

### Configuring Peer Discovery

The client supports two modes of peer discovery: DNS with IRC as fallback.

If you want to run a DNS server to help enable peer discovery, you can pass the `-dnsseed` flag.

If you wish to disable IRC discovery, that can be disabled via the `-noirc` flag.

If you wish to enable UPnP port forwarding for the client node, use the `-upnp` flag.

### Configuring Weavers

In order to effectively weave, you'll typically want to run one weaver per CPU core on your machine. This is configured via the `-numweavers` param, like so:

```
$ client ... -numweavers 4
```

To run a weaver-less node, you can pass `0` as the number of weavers like so:

```
$ client ... -numweavers 0
```

### Configuring Keys

The client supports two modes of pass point considerations for weaving: single key and key list targets.

To distribute pass points to a single key, use the `-pubkey` flag to pass the target public key in the CLI command.

To distribute pass points to multiple keys, use the `-keyfile` flag with a text file of the public keys (one per line).

> NOTE: The keyholder components `dumpkeys` command will generate a `keys.txt` for you as part of keyholder setup.

## Terminating the client

The client runs synchronously in the current window, so to exit simply hit control-c for a graceful shutdown.
