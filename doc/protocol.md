# Hercules Protocol

The transmitter splits the file into chunks of the same size. All the chunks are transmitted (in order).
The receiver acknowledges the chunks at regular intervals.
Once the sender has transmitted all chunks once, it will start to retransmit all chunks that have not been acknowledged in time. 
This is repeated until all chunks are acked.


---


All packets have the following basic layout:

	|  index  |  path  |  flags  | seqnr | payload ... |
	|   u32   |   u8   |    u8   |  u32  |     ...     |


> **NOTE**: Integers are transmitted little endian (host endianness).

The flags field is zero for regular data and (N)ACK packets.
The flags field has the lowest bit set for packets referring to the transfer
of a directory index.
The flags field is zero for initial packets, since those don't refer to
either in particular.

For control packets (handshake and acknowledgements, either sender to receiver or receiver to sender), index is `UINT_MAX`.
For all control packets, the first byte of the payload contains the control packet type.
The following control packet types exist:

    0: Handshake packet
    1: ACK packet
    2: NACK packet
    3: RTT measurement packet

For data packets (sender to receiver), the index field is the index of the chunk being transmitted.
This is **not** a packet sequence number, as chunks may be retransmitted; hence the separate field `seqnr` contains the per-path sequence number.
A NACK packet is always associated with a path. 

If path is not `UINT8_MAX`, it is used to account the packet to a specific path.
This is used to provide quick feedback to the PCC algorithm, if enabled.


#### Handshake

1. Sender sends initial packet:

        | filesize | chunksize | timestamp | path index | flags | index_len | dir_index... |
        |   u64    |   u32     |    u64    |    u32     |  u8   |    u64    |     ...      |
        
    Where `num entries` is `UINT8_MAX` to distinguish handshake replies from ACKs.
    
    Flags:
    - 0-th bit: `SET_RETURN_PATH` The receiver should use this path for sending
    ACKs from now on.
    - 1st bit: `HS_CONFIRM`: Indicates that the packet is a reflected HS packet, confirming the handshake.
    - 2nd bit: `NEW_TRANSFER`: Indicates that the packet is trying to start a new transfer (not just a path update).
    - 3rd bit: `INDEX_FOLLOWS`: The directory index is larger than the space available in the handshake packet, it will need to be transferred separately before the actual data transfer can start.

1. Receiver replies immediately with the same packet (with `HS_CONFIRM` set).

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

