// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HERCULES_SCION_H
#define HERCULES_SCION_H

#define SCION_ENDHOST_PORT 30041
#define SCION_HEADER_LINELEN 4
#define SCION_HEADER_HBH 200
#define SCION_HEADER_E2E 201

#pragma pack(push)
#pragma pack(1)

// XXX this should work in practice, according to:
// https://stackoverflow.com/questions/15442536/why-ip-header-variable-declarations-are-swapped-depending-on-byte-order
struct scionhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int version : 4;
	unsigned int qos : 8;
	unsigned int flow_id : 20;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int flow_id : 20;
	unsigned int qos : 8;
	unsigned int version : 4;
#else
#error "Please fix <packet.h>"
#endif
	/** Type of the next header */
	__u8 next_header;
	/** Header length that includes the path */
	__u8 header_len;
	/** Total Length of the payload */
	__u16 payload_len;
	/** SCION path type */
	__u8 path_type;
	/** Type of destination address */
	unsigned int dst_type : 2;
	/** Type of source address */
	unsigned int src_type : 2;
	/** Length of destination address */
	unsigned int dst_len : 2;
	/** Length of source address */
	unsigned int src_len : 2;
	__u16 reserved;
};

struct scionaddrhdr_ipv4 {
	__u64 dst_ia;
	__u64 src_ia;
	__u32 dst_ip;
	__u32 src_ip;
};

struct hercules_header {
	__u32 chunk_idx;
	__u8 path;
	__u32 seqno;
};

// Structure of first RBUDP packet sent by sender.
// Integers all transmitted in little endian (host endianness).
struct rbudp_initial_pkt {
	__u64 filesize;
	__u32 chunklen;
	__u32 etherlen;
	__u64 timestamp;
	__u8 path_index;
	__u8 flags;
	__u32 name_len;
	__u8 name[];
};

#define HANDSHAKE_FLAG_SET_RETURN_PATH 0x1u
#define HANDSHAKE_FLAG_HS_CONFIRM (0x1u << 1)
#define HANDSHAKE_FLAG_NEW_TRANSFER (0x1u << 2)

// Structure of ACK RBUDP packets sent by the receiver.
// Integers all transmitted in little endian (host endianness).
struct rbudp_ack_pkt {
	__u8 num_acks;	//!< number of (valid) entries in `acks`
	__u32 max_seq;
	__u32 ack_nr;
	__u64 timestamp;
	struct {
		__u32 begin;  //!< index of first chunk that is ACKed with this range
		__u32 end;	  //!< one-past-the-last chunk that is ACKed with this range
	} acks[256];	  //!< list of ranges that are ACKed
};

#define CONTROL_PACKET_TYPE_INITIAL 0
#define CONTROL_PACKET_TYPE_ACK 1
#define CONTROL_PACKET_TYPE_NACK 2

struct hercules_control_packet {
	__u8 type;
	union {
		struct rbudp_initial_pkt initial;
		struct rbudp_ack_pkt ack;
	} payload;
};

#pragma pack(pop)

// XXX This is placed here (instead of in hercules.h) to avoid clang from
// complainig about atomics when building redirect_userspace.c with hercules.h
// included.

// Connection information
struct hercules_app_addr {
	/** SCION IA. In network byte order. */
	__u64 ia;
	/** SCION IP. In network byte order. */
	__u32 ip;
	/** SCION/UDP port (L4, application). In network byte order. */
	__u16 port;
};
typedef __u64 ia;
#define MAX_NUM_SOCKETS 256

#endif	// HERCULES_SCION_H
