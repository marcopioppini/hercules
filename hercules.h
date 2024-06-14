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

#include "bpf/src/xsk.h"
#include "congestion_control.h"
#include "frame_queue.h"
#include "packet.h"

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
	__u64 next_handshake_at;
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
	u64 rx_npkts;
};

// Information specific to the receiving side of a session
struct receiver_state {
	struct hercules_session *session;
	atomic_uint_least64_t handshake_rtt;
	/** Filesize in bytes */
	size_t filesize;
	/** Size of file data (in byte) per packet */
	u32 chunklen;
	/** Number of packets that will make up the entire file. Equal to
	 * `ceil(filesize/chunklen)` */
	u32 total_chunks;
	/** Memory mapped file for receive */
	char *mem;

	struct bitset received_chunks;

	// The reply path to use for contacting the sender. This is the reversed
	// path of the last initial packet with the SET_RETURN_PATH flag set.
	// TODO needs atomic? -> perf?
	struct hercules_path reply_path;

	// Start/end time of the current transfer
	u64 start_time;
	u64 end_time;
	u64 last_pkt_rcvd;	// Timeout detection
	u8 num_tracked_paths;
	bool is_pcc_benchmark;
	struct receiver_state_per_path path_state[256];
};

/// SENDER

// Used to atomically swap in new paths
struct path_set {
	u64 epoch;
	u32 n_paths;
	u8 path_index;	// Path to use for sending next batch (used by tx_p)
	struct hercules_path paths[256];
};

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
	size_t prev_tx_npkts_queued;
	_Atomic u32 rate_limit;
	u64 prev_round_start;
	u64 prev_round_end;
	u64 prev_slope;
	u64 ack_wait_duration;
	u32 prev_chunk_idx;
	bool finished;
	struct bitset acked_chunks;			  //< Chunks we've received an ack for
	atomic_uint_least64_t handshake_rtt;  // Handshake RTT in ns

	struct path_set *_Atomic pathset;  // Paths currently in use
	struct thread_epoch
		*epochs;	 // Used for threads to publish their current pathset epoch
	u32 next_epoch;	 // Used by the thread updating the pathsets

	/** Filesize in bytes */
	size_t filesize;
	char filename[100];
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
};

/// SESSION
// Some states are used only by the TX/RX side and are marked accordingly
enum session_state {
	SESSION_STATE_NONE,
	SESSION_STATE_PENDING,	//< (TX) Need to send HS and repeat until TO,
							// waiting for a reflected HS packet
	SESSION_STATE_NEW,	//< (RX) Received a HS packet, need to send HS reply and
						// CTS
	SESSION_STATE_WAIT_CTS,	 //< (TX) Waiting for CTS
	SESSION_STATE_RUNNING,	 //< Transfer in progress
	SESSION_STATE_DONE,		 //< Transfer done (or cancelled with error)
};

enum session_error {
	SESSION_ERROR_OK,		//< No error, transfer completed successfully
	SESSION_ERROR_TIMEOUT,	//< Session timed out
	SESSION_ERROR_STALE,	//< Packets are being received, but none are new
	SESSION_ERROR_PCC,		//< Something wrong with PCC
	SESSION_ERROR_SEQNO_OVERFLOW,
	SESSION_ERROR_NO_PATHS,	   //< Monitor returned no paths to destination
	SESSION_ERROR_CANCELLED,   //< Transfer cancelled by monitor
	SESSION_ERROR_BAD_MTU,	   //< Invalid MTU supplied by the monitor
	SESSION_ERROR_MAP_FAILED,  //< Could not mmap file
	SESSION_ERROR_INIT,		   //< Could not initialise session
};

// A session is a transfer between one sender and one receiver
struct hercules_session {
	struct receiver_state *rx_state;  //< Valid if this is the receiving side
	struct sender_state *tx_state;	  //< Valid if this is the sending side
	_Atomic enum session_state state;
	_Atomic enum session_error error;  //< Valid if the session's state is DONE
	struct send_queue *send_queue;

	u64 last_pkt_sent;
	u64 last_pkt_rcvd;		//< Used for timeout detection
	u64 last_new_pkt_rcvd;	//< If we only receive packets containing
							// already-seen chunks for a while something is
							// probably wrong
	u32 jobid;				//< The monitor's ID for this job
	u32 payloadlen;	 //< The payload length used for this transfer. Note that
					 // the payload length includes the rbudp header while the
					 // chunk length does not.

	struct hercules_app_addr peer;

	// Number of sent/received packets (for stats)
	size_t rx_npkts;
	size_t tx_npkts;
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

// Config determined at program start
struct hercules_config {
	u32 xdp_flags;
	int xdp_mode;
	int queue;
	bool configure_queues;
	struct hercules_app_addr local_addr;
};

struct hercules_server {
	struct hercules_config config;
	int control_sockfd;	 // AF_PACKET socket used for control traffic
	int usock;			 // Unix socket used for communication with the monitor
	int max_paths;
	int rate_limit;
	int n_threads;					   // Number of RX/TX worker threads
	struct worker_args **worker_args;  // Args passed to RX/TX workers

	struct hercules_session *_Atomic session_tx;  // Current TX session
	struct hercules_session *deferred_tx;  // Previous TX session, no longer
										   // active, waiting to be freed
	struct hercules_session *_Atomic session_rx;  // Current RX session
	struct hercules_session *deferred_rx;

	bool enable_pcc;  // TODO make per path or session or something
	int *ifindices;
	int num_ifaces;
	struct hercules_interface ifaces[];
};

/// XDP
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct frame_queue available_frames;
	// TODO ok to have locks closeby?
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

/// STATS TODO
struct path_stats_path {
	__u64 total_packets;
	__u64 pps_target;
};

struct path_stats {
	__u32 num_paths;
	struct path_stats_path paths[1];  // XXX this is actually used as a dynamic
									  // struct member; the 1 is needed for CGO
};
struct path_stats *make_path_stats_buffer(int num_paths);

struct hercules_stats {
	__u64 start_time;
	__u64 end_time;
	__u64 now;

	__u64 tx_npkts;
	__u64 rx_npkts;

	__u64 filesize;
	__u32 framelen;
	__u32 chunklen;
	__u32 total_chunks;
	__u32 completed_chunks;	 //!< either number of acked (for sender) or
							 //!< received (for receiver) chunks

	__u32 rate_limit;
};

#endif	// __HERCULES_H__

/// Local Variables:
/// outline-regexp: "/// "
/// eval:(outline-minor-mode 1)
/// End:
