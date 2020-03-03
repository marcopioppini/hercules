# Hercules

High speed bulk data transfer application.

This is a proof of concept implementation of file transfer using SCION/UDP (over ethernet/IPv4/UDP).
To achieve high transmit and receive rates, the `hercules` tool is implemented using `AF_XDP`.
On suitable hardware, a single instance can achieve >30Gbps transfer rate, and multiple instances can run in parallel on different network interfaces.

`hercules` is not a daemon, it performs for only a single file transmission and then stops. 
There are exactly two hosts involved; the _sender_ transmits data to the _receiver_.
The receiver waits for the sender to start the transmission.
There is no authorization, access control etc. The idea is that this will be integrated in a more generic framework that does all of that (e.g. make this run as an FTP extension).

## Building

Option
1. Build in Docker, using the `Dockerfile` and `Makefile` provided in the repo; just run `make`.

1. Build using `go build`
  
   Requires:
    - gcc/clang
    - linux kernel headers >= 4.8
    - go >= 1.11


## Running

> **WARNING**: network drivers seem to crash occasionally.

> **NOTE**: if hercules is aborted forcefully (e.g. while debugging), it can leave an XDP program loaded which will prevent starting again.
						Run `ip link set dev <device> xdp off`.

> **NOTE**: many things can go wrong, expect to diagnose things before getting it to work.


1. Make sure that SCION endhost services (sciond, dispatcher) are configured and running on both sender and receiver machines

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


* Both `<receiver addr>` and `<sender addr>` are SCION/IPv4 addresses with UDP port, e.g. `17-ffaa:0:1102,[172.16.0.1]:10000`
* The `numactl` is optional but has a huge effect on performance on systems with multiple numa nodes.
* See source code for additional options


## Protocol

The transmitter splits the file into chunks of the same size. All the chunks are transmitted (in order).
The receiver acknowledges the chunks at regular intervals.
Once the sender has transmitted all chunks once, it will start to retransmit all chunks that have not been acknowledge in time. 
This is repeated until all chunks are acked.


---


All packets have the following basic layout:

	|  index  |  payload ... |
	|   u32   |    ...       |


> **NOTE**: Integers are transmitted little endian (host endianness).

For control packets (handshake and acknowledgements, either sender to receiver or receiver to sender), index is `UINT_MAX`.
For data packets (sender to receiver), the index field is the index of the chunk being transmitted. This is **not** a packet sequence number, as chunks may be retransmitted.



#### Handshake

1. Sender sends initial packet:

        | filesize | chunksize | timestamp |
        |   u64    |   u32     |    u64    |

1. Receiver replies immediately with the same packet.

    This first packet is used to determine an approximate round trip time.
    
	The receiver proceeds to  prepare the file mapping etc.

1. Receiver replies with an empty ACK signaling "Clear to send"

#### Data transmit

* The sender sends (un-acknowledged) chunks in data packets at chosen send rate
* The receiver sends ACK packets for the entire file at 100ms intervals.
    
  ACK packets consist of a list of `begin`,`end` pairs declaring that chunks
  with index `i` in `begin <= i < end` have been received.
  Lists longer than the packet payload size are transmitted as multiple 
  independent packets with identical structure.


        | num entries | begin, end | begin, end | begin, end | ...
        |    u8       |  u32   u32 |  u32   u32 |  u32   u32 | ...


#### Termination

1. Once the receiver has received all chunks, it sends one more ACK for the entire range and terminates.
1. When the sender receives this last ACK, it determines that all chunks have been received and terminates.

## Issues, Todos, Future Work

* [ ] Flow control: if the receiver is slower than the sender (e.g. because it needs to write stuff to disk) it just drops packets.
	  The congestion control naturally solves this too, but is fairly slow to adapt.
	  Maybe a simple window size would work.
* [ ] Abort of transmission not handled (if one side is stopped, the other side will wait forever).
* [ ] Jumbo frames; requires increasing FRAME_SIZE (but there are additional limitations, since "XDP doesn't support packets spanning more than one memory page.")
* [ ] (Huge) Move SCION packet parsing & port dispatching to an XDP program;
      Allows that SCION traffic can go through while hercules is running & allows running multiple instances of hercules on same NIC.
* [ ] Use multiple paths; some tricky parts may be "load balancing", splitting the congestion control and applying separate rate limits.
* [ ] Replace paths used for sending before they expire (for very long transmissions)
* [ ] Optimisations; check sum computations, file write (would be broken for huge files), ...
