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

#ifndef __HERCULES_H__
#define __HERCULES_H__

#include <linux/types.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "bpf/src/xsk.h"
#include "congestion_control.h"
#include "frame_queue.h"
#include "packet.h"
#include "errors.h"

// The version is included in the packet headers.
// We check whether the version of received packets matches ours.
// If you make incompatible changes to the headers or Hercules' behaviour,
// change this version to avoid incompatible servers interacting.
#define HERCULES_HEADER_VERSION 1
// Default config file
#define HERCULES_DEFAULT_CONFIG_PATH "/usr/local/etc/hercules.conf"
// Config file in current working dir
#define HERCULES_CWD_CONFIG_PATH "hercules.conf"
#define HERCULES_MAX_HEADERLEN 256
// NOTE: The maximum packet size is limited by the size of a single XDP frame
// (page size - metadata overhead). This is around 3500, but the exact value
// depends on the driver. We're being conservative here. Support for larger
// packets is possible by using xdp in multibuffer mode, but this requires code
// to handle multi-buffer packets.
#define HERCULES_MAX_PKTSIZE 3000
#define HERCULES_FILENAME_SIZE 1000
// Batch size for send/receive operations
#define BATCH_SIZE 64
// Number of frames in UMEM area
#define NUM_FRAMES (4 * 1024)

struct hercules_path_header {
	const char header[HERCULES_MAX_HEADERLEN];	//!< headerlen bytes
	__u16 checksum;	 // SCION L4 checksum over header with 0 payload
};

// Path are specified as ETH/IP/UDP/SCION/UDP headers.
struct hercules_path {
	_Atomic __u64 next_handshake_at;
	int nack_errs;
	int headerlen;
	int payloadlen;
	int framelen;  //!< length of ethernet frame; headerlen + payloadlen
	int ifid;	   // Interface to use for sending
	struct hercules_path_header header;
	atomic_bool enabled;  // Paths can be disabled, e.g. in response to
						  // receiving SCMP errors
	struct ccontrol_state *cc_state;  // This path's PCC state
};

/// RECEIVER
// Per-path state at the receiver
struct receiver_state_per_path {
	struct bitset seq_rcvd;
	sequence_number nack_end;
	sequence_number prev_nack_end;
	_Atomic u64 rx_npkts;
};

// Information specific to the receiving side of a session
struct receiver_state {
	struct hercules_session *session;
	atomic_uint_least64_t handshake_rtt;
	/** Filesize in bytes */
	size_t filesize;
	size_t index_size;	// Size of the directory index in bytes.
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to
	 * `ceil(filesize/chunklen)` */
	u32 total_chunks;
	u32 index_chunks;
	/** Memory mapped file for receive */
	char *mem;
	char *index;

	struct bitset received_chunks;	// Bitset for marking received DATA chunks
	struct bitset received_chunks_index;  // Bitset for received IDX chunks

	// The reply path to use for contacting the sender. This is the reversed
	// path of the last initial packet with the SET_RETURN_PATH flag set.
	// XXX (Performance) Some form of synchronisation is required for
	// reading/writing the reply path. Even though it's marked atomic, atomicity
	// of updates is ensured using locks behind the scenes (the type is too
	// large). Could be optimised by making it a pointer.
	_Atomic struct hercules_path reply_path;

	u32 ack_nr;
	u64 next_nack_round_start;
	u64 next_ack_round_start;
	_Atomic u8 num_tracked_paths;
	bool is_pcc_benchmark;
	struct receiver_state_per_path path_state[256];
	u16 src_port;	 // The UDP/SCION port to use when sending packets (LE)
	u64 start_time;	 // Start/end time of the current transfer
	u64 end_time;
	u64 sent_initial_at;
};

/// SENDER

// Used to atomically swap in new paths
struct path_set {
	u64 epoch;	// Epoch value of this path set. Set by the updating thread.
	u32 n_paths;
	u8 path_index;	// Path to use for sending next batch (used by tx_p)
	struct hercules_path paths[256];
};

// When a thread reads the current path set it published the epoch value of the
// set it read to let the updating thread know when it has moved on to the new
// pathset and it's thus safe to free the previous one.
// These should occupy exactly one cache line to stop multiple threads from
// frequently writing to the same cache line.
struct thread_epoch {
	_Atomic u64 epoch;
	u64 _[7];
};
_Static_assert(sizeof(struct thread_epoch) == 64,
			   "struct thread_epoch must be cacheline-sized");

struct sender_state {
	struct hercules_session *session;

	// State for transmit rate control
	size_t tx_npkts_queued;
	u64 prev_rate_check;
	u64 rate_limit_wait_until;
	u64 next_ack_due;
	size_t prev_tx_npkts_queued;
	_Atomic u32 rate_limit;
	u64 prev_round_start;
	u64 prev_round_end;
	u64 prev_slope;
	u64 ack_wait_duration;
	u32 prev_chunk_idx;
	bool finished;

	struct bitset acked_chunks;			  //< Chunks we've received an ack for
	struct bitset acked_chunks_index;	  //< Chunks we've received an ack for
	atomic_uint_least64_t handshake_rtt;  // Handshake RTT in ns

	struct path_set *_Atomic pathset;  // Paths currently in use
	struct thread_epoch
		*epochs;	 // Used for threads to publish their current pathset epoch
	u32 next_epoch;	 // Used by the thread updating the pathsets

	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to
	 * `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;
	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;

	u32 index_chunks;  // Chunks that make up the directory index
	char *index;
	size_t index_size;			// Size of the directory index in bytes
	bool needs_index_transfer;	// Index does not fit in initial packet and
								// needs to be transferred separately

	u16 src_port;  // UDP/SCION port to use when sending packets
};

/// SESSION

// A session is a transfer between one sender and one receiver
struct hercules_session {
	struct receiver_state *rx_state;  //< Valid if this is the receiving side
	struct sender_state *tx_state;	  //< Valid if this is the sending side
	_Atomic enum session_state state;
	_Atomic enum session_error error;
	struct send_queue *send_queue;

	u64 last_pkt_sent;		//< Used for HS retransmit interval
	_Atomic u64 last_pkt_rcvd;		//< Used for timeout detection
	_Atomic u64 last_new_pkt_rcvd;	//< If we only receive packets containing
							// already-seen chunks for a while something is
							// probably wrong. (Only used by receiver)
	u64 last_path_update;
	u64 last_monitor_update;

	_Atomic size_t rx_npkts;  // Number of sent/received packets (for stats)
	_Atomic size_t tx_npkts;

	struct hercules_app_addr peer;	//< UDP/SCION address of peer (big endian)
	u64 jobid;						//< The monitor's ID for this job
	u32 payloadlen;	 //< The payload length used for this transfer. Note that
					 // the payload length includes the rbudp header while the
					 // chunk length does not.
};

/// SERVER
struct hercules_interface {
	char ifname[IFNAMSIZ];
	int ifid;
	int queue;
	u32 prog_id;
	int ethtool_rule;
	u32 num_sockets;
	struct xsk_umem_info *umem;
	struct xsk_socket_info **xsks;
};

// Values obtained from config file (or defaults)
struct hercules_config {
	char *monitor_socket;
	char *server_socket;
	uid_t drop_uid;
	gid_t drop_gid;
	u32 xdp_flags;
	int xdp_mode;
	int queue;
	bool configure_queues;
	bool enable_pcc;
	int rate_limit;	 // Sending rate limit, only used when PCC is enabled
	int n_threads;	 // Number of RX/TX worker threads
	struct hercules_app_addr local_addr;
	u16 port_min;  // Lowest port on which to accept packets (in HOST
				   // endianness)
	u16 port_max;  // Highest port, host endianness
};

struct hercules_server {
	struct hercules_config config;
	int control_sockfd;	 // AF_PACKET socket used for control traffic
	int usock;			 // Unix socket used for communication with the monitor
	struct worker_args **worker_args;  // Args passed to RX/TX workers

	struct hercules_session *_Atomic
		sessions_tx[HERCULES_CONCURRENT_SESSIONS];	// Current TX sessions
	struct hercules_session
		*deferreds_tx[HERCULES_CONCURRENT_SESSIONS];  // Previous TX sessions,
													  // no longer active,
													  // waiting to be freed
	struct hercules_session *_Atomic
		sessions_rx[HERCULES_CONCURRENT_SESSIONS];	// Current RX sessions
	struct hercules_session
		*deferreds_rx[HERCULES_CONCURRENT_SESSIONS];  // Previous RX sessions,
													  // waiting to be freed

	unsigned int *ifindices;
	int num_ifaces;
	struct hercules_interface ifaces[];
};

/// XDP
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct frame_queue available_frames;
	// XXX (Performance) Do we need to ensure spinlocks are in different
	// cachelines?
	pthread_spinlock_t fq_lock;	 // Lock for the fill queue (fq)
	pthread_spinlock_t
		frames_lock;  // Lock for the frame queue (available_frames)
	struct xsk_umem *umem;
	void *buffer;
	struct hercules_interface *iface;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
};

typedef int xskmap;

/// Thread args
struct worker_args {
	u32 id;
	struct hercules_server *server;
	struct xsk_socket_info *xsks[];
};

#endif	// __HERCULES_H__

/// Local Variables:
/// outline-regexp: "/// "
/// eval:(outline-minor-mode 1)
/// End:
