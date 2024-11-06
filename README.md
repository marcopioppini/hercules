# Hercules

Hercules is a high-speed [SCION](scion-architecture.net)-native bulk data transfer application.

Hercules achieves high transfer rates by combining the Linux kernel `AF_XDP` express data path and PCC congestion control with a custom data transfer protocol.
Hercules can take advantage of SCION's native multipath capabilities to transfer data using multiple network paths simultaneously.

The Hercules server is intended to run on dedicated machines.
Clients submit transfer jobs to Hercules via a HTTP API. The server may handle multiple concurrent transfers in both the sending and receiving direction.
Hercules supports transferring entire directories in one go.

## Prerequisites

To run Hercules, the machine on which you plan to install it must have a working SCION endhost stack.
See [HERE](https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html) for how to set that up.

Hercules relies on `AF_XDP` and loads an XDP program on the interface it uses. Make sure you have no other programs that want to attach XDP programs to the same interface.

## Overview

A Hercules server installation consists of two components, i.e.,
two separate processes that communicate via a Unix socket.

- The monitor (`hercules-monitor`) is responsible for handling SCION paths and
  exposes a HTTP API which clients can use to submit new transfers, check the
  status of ongoing transfers, or cancel them.
- The server (`hercules-server`) carries out the actual file transfers.

The monitor and server processes must be started and stopped together, you
should not restart one without also restarting the other.
The provided systemd service files ensure this, if you use a different method
to run Hercules you must ensure this yourself.

Clients interact with Hercules via its HTTP API.
You may use this API directly (see [the API docs](doc/api.md)), but the easiest way for users to transfer files is using the provided `hcp` command line tool.
Integration with FTS/gfal2 is also possible via a plugin, see the [`gfal2-hercules`](./gfal2-hercules/) directory for more information.

## Getting started

The following should help you get started with Hercules.

### Installing 

To install Hercules, you may build it yourself from source
(see ["Building from Source"](#building-from-source)) or use the provided packages.
TODO packages.

### Configuration

> For more information, see the Hercules monitor's manual
> ([hercules-monitor(1)](doc/hercules-monitor.1.md)), the Hercules server's manual
> ([hercules-server(1)](doc/hercules-server.1.md)), and the Hercules configuration
> manual ([hercules.conf(5)](doc/hercules.conf.5.md)).
> The manuals are installed alongside Hercules, if you used the packages
> or `make install`.

Hercules is configured using a configuration file.
The default configuration file is `/usr/local/etc/hercules.conf`.

To get started, filling in the following information is required:

- Change `ListenAddress` to the SCION/UDP address and port your Hercules instance should listen on.
- Replace the entry in `Interfaces` with the network interface Hercules should use.

In both cases you should replace the entire string, including the `replaceme//` markers.

While the above two settings are sufficient to run Hercules, we **strongly recommend** additionally setting the options `DropUser` and/or `ChrootDir`.
Hercules will then drop its privileges to the specified user after startup and thus use the provided user's permissions and path to restrict filesystem access.
Hence, you should ensure the specified user has the appropriate read/write permissions on the paths you intend to send from/receive to.
If you omit this option, Hercules will run as root.
See [the configuration documentation](doc/hercules.conf.5.md#CAVEATS) for a discussion of the security implications.

See [hercules(5)](doc/hercules.conf.5.md) or the sample configuration file, [`hercules.conf.sample`](hercules.conf.sample) for an example illustrating all
available configuration options.

### Starting Hercules

To start the Hercules server, you may use `systemctl start hercules-server`, if you installed Hercules as described above.
This will start both the server and monitor processes.
You can check their status and log output via `systemctl status hercules-server` or `systemctl status hercules-monitor`, respectively.
If the `hercules-server` process fails to start with `Error in XDP setup!`, the cause is likely either that your setup requires specifying `ConfigureQueues = false` in the config file, or that an XDP program is already loaded on the specified network interface. See the section "[Troubleshooting](#troubleshooting)" below for more information.

### Submitting a Transfer

Transfers can be submitted to Hercules via its HTTP API.
A user submits his transfer to the sending-side (source) Hercules server. The user does not interact with the receiving-side (destination) Hercules server.
The easiest way to transfer files is using the provided `hcp` utility.
For example, assume we have two hosts with Hercules set up, `hercules1` and `hercules2` and wish to copy the file `/tmp/data/myfile` from `hercules1` to `/mnt/storage/myfile` on `hercules2`.
To do so, we need to know the IP address and port the source Hercules server's API is exposed on, as well as the SCION/UDP address and port the destination Hercules server on `hercules2` is listening on.
The HTTP API is exposed on port 8000 by default.
If you followed this guide, you should have set the destinations listening address in `hercules2`'s configuration file.
Let's assume, for this example, that the server on `hercules2` is listening on `64-2:0:c,10.0.0.12:10000`.
Then, running the following from `hercules1` will transfer the file, giving a progress report while the transfer is running:
``` shell
$ hcp localhost:8000 /tmp/data/myfile 64-2:0:c,10.0.0.12:10000 /mnt/storage/myfile
```

Note that in the above example we specified `localhost:8000` as the first argument since we submitted the transfer from the very host the source Hercules server is running on.
In practice, `hcp` may be run from a different host, such as a user's machine, too.
In that case, the first argument should be substituted with the listening address of the source server's HTTP API, e.g., `10.10.10.10:8000`.
Note however, that the paths are still relative to the source and destination servers, respectively.
This also implies that the file to be transferred must first be made available to the source Hercules server somehow. This could be done in several ways, e.g., by plugging in a physical disk or via a network share.

See [the hcp manual](hcp/hcp.1.md) for more information about the `hcp` tool.
If you wish to use the API directly, see [the API docs](doc/api.md) for its description.

## Building from Source

Clone this git repository and change to the directory you cloned it to.
Before building Hercules, you must run `git submodule update --init` to download some required dependencies.
You can then build Hercules, either using Docker or natively.

### Building with Docker

Hercules can be built from source using Docker and the provided `Dockerfile` which prepares the required build environment.

To build Hercules using Docker, simply run `make docker_all`.
This will build the server and monitor executables, as well as the `hcp` tool.

> You may prefix any of the makefile targets with `docker_` to use Docker
> instead of your native environment.

### Native Build

To build Hercules without Docker, you must have the following installed:

+ llvm
+ clang
+ git
+ Go >= 1.22
+ libz
+ libelf
+ Linux kernel headers
+ gcc-multilib

On Ubuntu you can install the required packages as follows:
`# apt install build-essential llvm clang git golang libz-dev libelf-dev
linux-headers-generic gcc-multilib`

To build Hercules, run `make all`.
This will build the server and monitor executables, as well as the `hcp` tool.

## Installing

Once built, you can install Hercules to your machine with `sudo make install`.
By default, this will install Hercules to `/usr/local/`.

## Debugging and Development

See the [developer guide](doc/developers.md).
The file also contains instructions on how to build packages.

## Troubleshooting

- If Hercules is aborted forcefully (e.g. while debugging) or crashes, it can leave an XDP program loaded which will prevent the server from starting again, yielding the following error message:
  ```text
  libbpf: Kernel error message: XDP program already attached
  Error loading XDP redirect, is another program loaded?
  Error in XDP setup!
  ```
  To remove the XDP program from the interface, run `ip link set dev <device> xdp off`.
  
  
- Some network cards support multiple receive queues.
  In such a case, it must be ensured that all incoming Hercules packets are sent to the same queue.
  Hercules will, by default, attempt to configure the queues accordingly.
  However this fails when using network cards that do not support multiple queues, yielding the following error message:
  ```text
  rxclass: Cannot get RX class rule count: Operation not supported
  Cannot insert classification rule
  could not configure queue 0 on interface ens5f0, abort
  Error in XDP setup!
  ```
  To resolve this, specify `ConfigureQueues = false` in the configuration file.
  
- The sending-side Hercules attempts to start a transfer, but the receiver does not show any indication of a received packet and the transfer times out.

  Hercules attempts to automatically pick the right packet size based on the MTU in the SCION path metadata and the sending interface.
  In some cases, however, this information is not accurate and the really supported MTU is smaller.
  To work around this, you can manually specify the payload size to be used, e.g., by supplying the `-l` option to `hcp`, or by specifying the payload length on a per-destination basis in the configuration file.
  
## Performance Configuration

Depending on your performance requirements and your specific bottlenecks, the following configuration options may help improve performance:

- On machines with multiple NUMA nodes, it may be beneficial to bind the Hercules server process to CPU cores "closer" to the network card. 
  To do so, install the `numactl` utility and adjust the file `/usr/local/lib/systemd/system/hercules-server.service` so it reads `ExecStart=/usr/bin/numactl -l --cpunodebind=netdev:<device> -- /usr/local/bin/hercules-server`, replacing `<device>` with your network interface.

- Setting the option `XDPZeroCopy = true` can substantially improve performance, but whether it is supported depends on the combination of network card and driver in your setup.

- Increasing the number of worker threads via the option `NumThreads` can also improve performance.

- Especially on machines with few CPU cores the options `TxOnly` and `RxOnly` will improve performance.

