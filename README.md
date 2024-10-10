# Hercules-server
## Overview
This version of Hercules consists of two components:

- The monitor (Go) is responsible for handling SCION paths and exposes a HTTP API which clients can use to submit new transfers, check the status of ongoing transfers, or cancel them.
- The server (C) carries out the actual file transfers.

Unlike previously, these are two separate processes that communicate via a unix socket.
They share a configuration file, the simplest version of which is in `hercules.conf`; see `sampleconf.toml` for all options.

## Changes from regular Hercules
The following should be the most important changes:

- Split C and Go parts into dedicated processes, with a unix socket between them.
- This is now a server, i.e. intended to run forever, not just a single-transfer application.
- No command line arguments (except for, optionally, the config file path), all options set in config file.
- The sender includes the destination file path for the receiver to use in the setup handshake.
CAVEAT: No checks on that path at the moment, so any file on the destination can be overwritten.
- Multiple concurrent transfers (both rx and tx) are supported (up to `HERCULES_CONCURRENT_SESSIONS`).
- Only 1 destination per transfer, the idea is to submit the transfer once per destination if multiple are needed.
- Transfer of entire directories is supported: If the source path is a directory, Hercules will try to recursively transfer the entire directory.
- In order to inform the receiver of the directory structure, a directory index is transferred at the beginning.
If this index is larger than the space available in the initial packet, a first phase of RBUDP is performed to transfer the index.
- Automatic MTU selection: At the start of a transfer, Hercules will pick the MTU (and, consequently, chunk length) that is as large as possible while still fitting on its selected paths.
This relies on the MTU in the path metadata, for the empty path the sending interface's MTU is used.
This behaviour can be overridden by manually supplying the desired payload length.
- The server will periodically update a transfer's paths by querying the monitor. The monitor will reply with the set of paths to use, which do not need to overlap with the previous set.
There is a restriction on path selection: All paths must be large enough to fit the payload length fixed at the beginning of the transfer.
- Implemented SCMP error handling: Upon receiving an error, the offending path will be disabled. It will be re-enabled if it is returned by the monitor in the next path update.
- Check the SCION/UDP source address/port of received packets match the expected values (i.e. the host that started the transfer).

## Getting started

### Building
First, run `git submodule update --init`.
Running `make` should build both the monitor and server. This uses the provided dockerfile.

### Running
On both the sender and the receiver:

- Fill in the provided `hercules.conf` with the host's SCION address and NIC
- First, start the monitor: `./hercules-monitor`.
- If there is already an XDP program loaded on the interface, you first have to remove it (e.g. `ip l set dev eth0 xdp off`)
- Depending on your network card/setup, you may want to specify `ConfigureQueues = false` in the config file. If you get an error related to XDP upon starting the server, try this.
Then, in a second shell, start the server: `./hercules-server`.

### Submitting a transfer
- To transfer `infile` from the sender to `outfile` at the receiver with address `64-2:0:c,148.187.128.136:8000`, run the following on the sender: `curl "localhost:8000/submit?file=infile&destfile=outfile&dest=64-2:0:c,148.187.128.136:8000"`.
- This should yield `OK 1`, where `1` is the submitted transfer's job id.
- You should see the transfer progress in the server's output at both the sender and receiver.
- It is also possible to query the transfer status via `curl "localhost:8000/status?id=1"`, though the output is not intended to be read by humans.

## Testing/Debugging

- It may be useful to uncomment some of the lines marked "for debugging" at the top of the Makefile.
- If you want to run under valgrind, passing `--fair-sched=yes` is helpful.
- The script `test.sh` will try 3 sets of transfers: a file, a directory, and 2 files concurrently.
In order to use it, adjust the definitions at the top of the file (hostnames, addresses and interfaces).
The script further relies on you having ssh keys set up for those two hosts.
Depending on the network cards you may need to comment in the two lines with `ConfigureQueues = false`.

## API
The Monitor's API supports the following operations via HTTP GET requests.

### `/submit`: Submitting a new transfer
Parameters:
- `file`: Path to source file, from the server's point of view
- `dest`: SCION address of the destination Hercules server
- `destfile`: Destination file path
- `payloadlen`: (Optional) override automatic MTU selection and use the specified payload length instead.

Example: `localhost:8000/submit?file=infile&destfile=outfile&dest=64-2:0:c,148.187.128.136:8000`

Returns: `OK id`, where `id` is an integer identifying the submitted job on success, an HTTP error code otherwise.

### `/status`: Check a transfer's status
Parameters:
- `id`: An id previously returned by `/submit`.

Returns: `OK status state error time_elapsed bytes_acked` on success, an HTTP error code otherwise.
- `status` is the monitor's internal transfer status and one of `TransferStatus`, as defined in the go code.
- `state` is an integer corresponding to the transfers current status (one of `session_state`, as defined in `errors.h`)
- `error` is an integer corresponding to the transfers error state (one of `session_error`, as defined in `errors.h`)
- `time_elapsed` is an integer representing the number of seconds elapsed since the server started this transfer.
- `bytes_acked` is the number of bytes acknowledged by the receiver.

### `/cancel`: Cancel a transfer
Parameters:
- `id`: An id previously returned by `/submit`.

Returns: `OK`on success, an HTTP error code otherwise.

### `/server`: Returns the server's SCION address
This functionality is provided for integration with FTS.

Parameters: None

Returns: `OK addr`, where `addr` is the server's SCION address.

### `/stat`: Retrieve stat information on a file
This is provided for compatibility with FTS, but also (optionally) used by hcp.

Parameters:
- `file`: Path to file

Returns: `OK exists size`, where `exists` is 1 if the file exists, 0 otherwise; `size` is the file's size in bytes.


# Readme not updated below this line.

# Hercules

High speed bulk data transfer application.

This is a proof of concept implementation of file transfer using SCION/UDP (over ethernet/IPv4/UDP).
To achieve high transmit and receive rates, the `hercules` tool is implemented using `AF_XDP`.
On suitable hardware, a single instance can achieve >98Gbps transfer rate, and multiple instances can run in parallel on different network interfaces.

`hercules` is not a daemon, it performs for only a single file transmission and then stops. 
There are at least two hosts involved; exactly one of which behaves as a _sender_, the remaining hosts behave as receiver.
The sender transmits the data to all receivers.
Each receiver waits for the sender to start the transmission.
There is no authorization, access control etc. The idea is that this will be integrated in a more generic framework that does all of that (e.g. make this run as an FTP extension).

## Building

Option
1. Build in Docker, using the `Dockerfile` and `Makefile` provided in the repo; just run `make`.

1. Build using `go build`
  
   Requires:
    - gcc/clang
    - linux kernel headers >= 5.0
    - go 1.21


## Running

> **WARNING**: network drivers seem to crash occasionally.

> **WARNING**: due to the most recent changes on the branch `multicore`, the rate-limit `computation` is a bit off.
  When setting the rate-limit with `-p`, keep this in mind and set a lower rate than you aim at.

> **NOTE**: if hercules is aborted forcefully (e.g. while debugging), it can leave an XDP program loaded which will prevent starting again.
						Run `ip link set dev <device> xdp off`.

> **NOTE**: many things can go wrong, expect to diagnose things before getting it to work.

> **NOTE**: Some devices use separate queues for copy and zero-copy mode (e.g. Mellanox).
  Make sure to use queues that support the selected mode.
  Additionally, you may need to postpone step 2 until the handshake has succeeded.

1. Make sure that SCION endhost services (sciond, dispatcher) are configured and running on both sender and receiver machines.
   For the most recent versions of Hercules, use a SCION version compatible to `https://github.com/scionproto/scion/releases/tag/v0.10.0`.

1. Configure queue network interfaces to particular queue (if supported by device); in this example queue 0 is used. 

    ```shell
    sudo ethtool -N <device> rx-flow-hash udp4 fn
    sudo ethtool -N <device> flow-type udp4 dst-port 30041 action 0
    ```

1. Start hercules on receiver side

    ```shell
    sudo numactl -l --cpunodebind=netdev:<device> -- \ 
        ./hercules -i <device> -q 0 -l <receiver addr> -o path/to/output/file.bin
    ```

1. Start hercules on sender side

    ```shell
    sudo numactl -l --cpunodebind=netdev:<device> -- \
        ./hercules -i <device> -q 0 -l <sender addr> -d <receiver addr> -t path/to/file.bin
    ```

* Both `<receiver addr>` and `<sender addr>` are SCION/IPv4 addresses with UDP port, e.g. `17-ffaa:0:1102,[172.16.0.1]:10000`.
* To send data to multiple receivers, just provide `-d` multiple times.
* The `numactl` is optional but has a huge effect on performance on systems with multiple numa nodes.
* The command above will use PCC for congestion control. For benchmarking, you might want to use `-pcc=false` and provide a maximum sending rate using `-p`.
* For transfer rates >30Gbps, you might need to use multiple networking queues. At the receiver this is currently only possible in combination with multiple IP addresses. 
* See source code (or `-h`) for additional options.
* You should be able to omit `-l`.
* For more sophisticated run configurations (e.g. using multiple paths), it is recommended to use a configuration file.
* When using 4 or more paths per destination, you might need to specify path preferences to make the path selection more efficient. 


## Protocol

The transmitter splits the file into chunks of the same size. All the chunks are transmitted (in order).
The receiver acknowledges the chunks at regular intervals.
Once the sender has transmitted all chunks once, it will start to retransmit all chunks that have not been acknowledge in time. 
This is repeated until all chunks are acked.


---


All packets have the following basic layout:

	|  index  |  path  | seqnr | payload ... |
	|   u32   |   u8   |  u32  |     ...     |


> **NOTE**: Integers are transmitted little endian (host endianness).

For control packets (handshake and acknowledgements, either sender to receiver or receiver to sender), index is `UINT_MAX`.
For all control packets, the first byte of the payload contains the control packet type.
The following control packet types exist:

    0: Handshake packet
    1: ACK packet
    2: NACK packet

For data packets (sender to receiver), the index field is the index of the chunk being transmitted.
This is **not** a packet sequence number, as chunks may be retransmitted; hence the separate field `seqnr` contains the per-path sequence number.
A NACK packet is always associated with a path. 

If path is not `UINT8_MAX`, it is used to account the packet to a specific path.
This is used to provide quick feedback to the PCC algorithm, if enabled.


#### Handshake

1. Sender sends initial packet:

        | num entries | filesize | chunksize | timestamp | path index | flags |
        |     u8      |   u64    |   u32     |    u64    |    u32     |  u8   |
        
    Where `num entries` is `UINT8_MAX` to distinguish handshake replies from ACKs.
    
    Flags:
    - 0-th bit: `SET_RETURN_PATH` The receiver should use this path for sending
    ACKs from now on.

1. Receiver replies immediately with the same packet.

    This first packet is used to determine an approximate round trip time.
    
	The receiver proceeds to  prepare the file mapping etc.

1. Receiver replies with an empty ACK signaling "Clear to send"

##### Path handshakes

Every time the sender starts using a new path or the receiver starts using a new
return path, the sender will update the RTT estimate used by PCC.
In order to achieve this, it sends a handshake (identical to the above) on the
affected path(s).
The receiver replies immediately with the same packet (using the current return path).

#### Data transmit

* The sender sends (un-acknowledged) chunks in data packets at chosen send rate
* The receiver sends ACK packets for the entire file at 100ms intervals.
    
  ACK packets consist of a list of `begin`,`end` pairs declaring that chunks
  with index `i` in `begin <= i < end` have been received.
  Lists longer than the packet payload size are transmitted as multiple 
  independent packets with identical structure.


        | begin, end | begin, end | begin, end | ...
        |  u32   u32 |  u32   u32 |  u32   u32 | ...

* The receiver sends a NACK packets four times per RTT to provide timely feedback to congestion control.
  The NACK packet layout is identical to the ACK packet layout.
       
  NACK packets are only sent if non-empty.
  Hence, if no path uses PCC, or no recent packet loss has been observed, no NACKs are sent. 

#### Termination

1. Once the receiver has received all chunks, it sends one more ACK for the entire range and terminates.
1. When the sender receives this last ACK, it determines that all chunks have been received and terminates.

## Issues, Todos, Future Work

* [ ] Flow control: if the receiver is slower than the sender (e.g. because it needs to write stuff to disk) it just drops packets.
	  The congestion control naturally solves this too, but is fairly slow to adapt.
	  Maybe a simple window size would work.
* [ ] Abort of transmission not handled (if one side is stopped, the other side will wait forever).
* [ ] Replace paths used for sending before they expire (for very long transmissions)
* [ ] Optimisations; check sum computations, file write (would be broken for huge files), ...
