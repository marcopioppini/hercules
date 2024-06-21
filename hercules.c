// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

// Enable extra warnings; cannot be enabled in CFLAGS because cgo generates a
// ton of warnings that can apparantly not be suppressed.
#pragma GCC diagnostic warning "-Wextra"
/* #pragma GCC diagnostic warning "-Wunused" */
/* #pragma GCC diagnostic warning "-Wpedantic" */

#include "hercules.h"
#include "packet.h"
#include <stdatomic.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fts.h>
#include <unistd.h>
#include <float.h>
#include <arpa/inet.h>
#include "linux/bpf_util.h"

#include "bpf/src/libbpf.h"
#include "bpf/src/bpf.h"
#include "bpf/src/xsk.h"
#include "linux/filter.h" // actually linux/tools/include/linux/filter.h

#include "frame_queue.h"
#include "bitset.h"
#include "libscion_checksum.h"
#include "congestion_control.h"
#include "utils.h"
#include "send_queue.h"
#include "bpf_prgms.h"
#include "monitor.h"
#include "xdp.h"

#define MAX_MIDDLEBOX_PROTO_EXTENSION_SIZE 128 // E.g., SCION SPAO header added by LightningFilter

#define L4_SCMP 202

#define RANDOMIZE_FLOWID

#define RATE_LIMIT_CHECK 1000 // check rate limit every X packets
// Maximum burst above target pps allowed
#define PATH_HANDSHAKE_TIMEOUT_NS 100e6 // send a path handshake every X=100 ms until the first response arrives

#define ACK_RATE_TIME_MS 100 // send ACKS after at most X milliseconds

static const int rbudp_headerlen = sizeof(struct hercules_header);
static const u64 session_timeout = 10e9; // 10 sec
static const u64 session_hs_retransmit_interval = 2e9; // 2 sec
static const u64 session_stale_timeout = 30e9; // 30 sec
#define PCC_NO_PATH UINT8_MAX // tell the receiver not to count the packet on any path
_Atomic bool wants_shutdown = false;

#define FREE_NULL(p) \
	do {             \
		free(p);     \
		p = NULL;    \
	} while (0);

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx, u8 flags,
						   sequence_number seqnr, const char *data, size_t n,
						   size_t payloadlen);

// Update header checksum according to packet contents
static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt);

void debug_print_rbudp_pkt(const char *pkt, bool recv);

static bool rbudp_check_initial(struct hercules_control_packet *pkt, size_t len, struct rbudp_initial_pkt **parsed_pkt);

static struct hercules_session *make_session(struct hercules_server *server);

/// COMMON

// Signal handler
void hercules_stop(int signo) {
	(void) signo;
	wants_shutdown = true;
}

// Check the SCION UDP address matches the session's peer
static inline bool src_matches_address(struct hercules_session *session,
								const struct scionaddrhdr_ipv4 *scionaddrhdr,
								const struct udphdr *udphdr) {
	/* struct hercules_app_addr *addr = &session->peer; */
	/* return scionaddrhdr->src_ia == addr->ia && */
	/* 	   scionaddrhdr->src_ip == addr->ip && udphdr->uh_sport == addr->port; */
	return true;
}

static void __exit_with_error(struct hercules_server *server, int error, const char *file, const char *func, int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error, strerror(error));
	if(server) {
		remove_xdp_program(server);
		unconfigure_rx_queues(server);
	}
	exit(EXIT_FAILURE);
}

#define exit_with_error(server, error) __exit_with_error(server, error, __FILE__, __func__, __LINE__)

static inline struct hercules_interface *get_interface_by_id(struct hercules_server *server, int ifid)
{
	for(int i = 0; i < server->num_ifaces; i++) {
		if(server->ifaces[i].ifid == ifid) {
			return &server->ifaces[i];
		}
	}
	return NULL;
}

// Mark the session as done and store why it was stopped.
// This may be called by any thread.
// Actually setting the session state to DONE should be done
// by the events_p thread.
static inline void quit_session(struct hercules_session *s,
								enum session_error err) {
	s->error = err;
}

static u32 ack__max_num_entries(u32 len)
{
	struct rbudp_ack_pkt ack; // dummy declval
	return umin32(UINT8_MAX - 1, (len - sizeof(ack.num_acks) - sizeof(ack.ack_nr) - sizeof(ack.max_seq) - sizeof(ack.timestamp)) / sizeof(ack.acks[0]));
}

static u32 ack__len(const struct rbudp_ack_pkt *ack)
{
	return sizeof(ack->num_acks) + sizeof(ack->ack_nr) + sizeof(ack->max_seq) + sizeof(ack->timestamp) + ack->num_acks * sizeof(ack->acks[0]);
}

// Send the *raw* packet pointed to by buf via the server's control socket.
// Used for transmitting control packets.
static void send_eth_frame(struct hercules_server *server,
						   const struct hercules_path *path, void *buf) {
	struct sockaddr_ll addr;
	// Index of the network device
	addr.sll_ifindex = path->ifid;
	// Address length
	addr.sll_halen = ETH_ALEN;
	// Destination MAC; extracted from ethernet header
	memcpy(addr.sll_addr, buf, ETH_ALEN);

	ssize_t ret = sendto(server->control_sockfd, buf, path->framelen, 0,
						 (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
	if (ret == -1) {
		exit_with_error(server, errno);
	}
}

static inline bool session_state_is_running(enum session_state s) {
	if (s == SESSION_STATE_RUNNING_IDX || s == SESSION_STATE_RUNNING_DATA) {
		return true;
	}
	return false;
}

#ifdef DEBUG_PRINT_PKTS
// recv indicates whether printed packets should be prefixed with TX or RX
void debug_print_rbudp_pkt(const char *pkt, bool recv) {
	struct hercules_header *h = (struct hercules_header *)pkt;
	const char *prefix = (recv) ? "RX->" : "<-TX";
	const u16 *src_port = (const u16 *) (pkt-8);
	const u16 *dst_port = (const u16 *) (pkt-6);
	printf("%s [%u -> %u] Header: Chunk %u, Path %u, Flags %s, Seqno %u\n", prefix,
		   ntohs(*src_port), ntohs(*dst_port), h->chunk_idx, h->path,(h->flags & PKT_FLAG_IS_INDEX) ? "IDX" : "DATA", h->seqno);
	if (h->chunk_idx == UINT_MAX) {
		// Control packets
		const char *pl = pkt + rbudp_headerlen;
		struct hercules_control_packet *cp =
			(struct hercules_control_packet *)pl;
		switch (cp->type) {
			case CONTROL_PACKET_TYPE_INITIAL:
				printf(
					"%s   HS: Filesize %llu, Chunklen %u, TS %llu, Path idx "
					"%u, Index size %llu, Flags %s|%s|%s|%s\n",
					prefix, cp->payload.initial.filesize,
					cp->payload.initial.chunklen, cp->payload.initial.timestamp,
					cp->payload.initial.path_index,
					cp->payload.initial.index_len,
					(cp->payload.initial.flags & HANDSHAKE_FLAG_SET_RETURN_PATH)
						? "RP"
						: "--",
					(cp->payload.initial.flags & HANDSHAKE_FLAG_HS_CONFIRM)
						? "HC"
						: "--",
					(cp->payload.initial.flags & HANDSHAKE_FLAG_NEW_TRANSFER)
						? "NT"
						: "--",
					(cp->payload.initial.flags & HANDSHAKE_FLAG_INDEX_FOLLOWS)
						? "IF"
						: "--");
				break;
			case CONTROL_PACKET_TYPE_ACK:
				printf("%s   ACK (%d) ", prefix, cp->payload.ack.num_acks);
				for (int r = 0; r < cp->payload.ack.num_acks; r++) {
					printf("[%d - %d] ", cp->payload.ack.acks[r].begin,
						   cp->payload.ack.acks[r].end);
				}
				printf("\n");
				break;
			case CONTROL_PACKET_TYPE_NACK:
				printf("%s   NACK (%d) ", prefix, cp->payload.ack.num_acks);
				for (int r = 0; r < cp->payload.ack.num_acks; r++) {
					printf("[%d - %d] ", cp->payload.ack.acks[r].begin,
						   cp->payload.ack.acks[r].end);
				}
				printf("\n");
				break;
			default:
				printf("%s   ?? UNKNOWN CONTROL PACKET TYPE", prefix);
				break;
		}
	} else {
		printf("%s   ** PAYLOAD **\n", prefix);
	}
}
#else
void debug_print_rbudp_pkt(const char * pkt, bool recv){
	(void)pkt;
	(void)recv;
	return;
}
#endif

static struct hercules_session *lookup_session_tx(struct hercules_server *server, u16 port){
	if (port < server->config.port_min || port > server->config.port_max){
		return NULL;
	}
	if (port == server->config.port_min){
		return NULL;
	}
	u32 off = port - server->config.port_min - 1;
	return server->sessions_tx[off];
}

static struct hercules_session *lookup_session_rx(struct hercules_server *server, u16 port){
	if (port < server->config.port_min || port > server->config.port_max){
		return NULL;
	}
	if (port == server->config.port_min){
		return NULL;
	}
	u32 off = port - server->config.port_min - 1;
	return server->sessions_rx[off];
}

// Initialise a new session. Returns null in case of error.
static struct hercules_session *make_session(struct hercules_server *server) {
	struct hercules_session *s;
	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	s->state = SESSION_STATE_NONE;
	s->error = SESSION_ERROR_NONE;
	int err = posix_memalign((void **)&s->send_queue, CACHELINE_SIZE,
							 sizeof(*s->send_queue));
	if (err != 0) {
		free(s);
		return NULL;
	}
	init_send_queue(s->send_queue, BATCH_SIZE);
	s->last_pkt_sent = 0;
	u64 now = get_nsecs();
	s->last_pkt_rcvd =
		now;  // Set this to "now" to allow timing out HS at sender
			  // (when no packet was received yet), once packets are
			  // received it will be updated accordingly
	s->last_new_pkt_rcvd = now;
	return s;
}

// Cleanup and free TX session
static void destroy_session_tx(struct hercules_session *session) {
	if (session == NULL) {
		return;
	}
	assert(session->state == SESSION_STATE_DONE);

	int ret = munmap(session->tx_state->mem, session->tx_state->filesize);
	assert(ret == 0);  // No reason this should ever fail
	session->tx_state->mem = NULL;

	bitset__destroy(&session->tx_state->acked_chunks);
	bitset__destroy(&session->tx_state->acked_chunks_index);
	struct path_set *pathset = session->tx_state->pathset;
	for (u32 i = 0; i < pathset->n_paths; i++){
		destroy_ccontrol_state(pathset->paths[i].cc_state, 0);
		pathset->paths[i].cc_state = NULL;
	}
	FREE_NULL(session->tx_state->pathset);
	FREE_NULL(session->tx_state->index);

	FREE_NULL(session->tx_state);

	destroy_send_queue(session->send_queue);
	FREE_NULL(session->send_queue);
	free(session);
}

// Cleanup and free RX session
static void destroy_session_rx(struct hercules_session *session) {
	if (session == NULL) {
		return;
	}
	assert(session->state == SESSION_STATE_DONE);

	int ret = munmap(session->rx_state->mem, session->rx_state->filesize);
	assert(ret == 0);  // No reason this should ever fail
	session->rx_state->mem = NULL;

	bitset__destroy(&session->rx_state->received_chunks);
	bitset__destroy(&session->rx_state->received_chunks_index);
	FREE_NULL(session->rx_state->index);
	FREE_NULL(session->rx_state);

	destroy_send_queue(session->send_queue);
	FREE_NULL(session->send_queue);
	free(session);
}

// Initialise the Hercules server. If this runs into trouble we just exit as
// there's no point in continuing.
struct hercules_server *hercules_init_server(
	int *ifindices, int num_ifaces, const struct hercules_app_addr local_addr,
	int queue, int xdp_mode, int n_threads, bool configure_queues,
	bool enable_pcc) {
	struct hercules_server *server;
	server = calloc(1, sizeof(*server) + num_ifaces * sizeof(*server->ifaces));
	if (server == NULL) {
		exit_with_error(NULL, ENOMEM);
	}

  server->usock = monitor_bind_daemon_socket();
  if (server->usock == 0) {
    fprintf(stderr, "Error binding daemon socket\n");
	exit_with_error(NULL, EINVAL);
  }
	server->ifindices = ifindices;
	server->num_ifaces = num_ifaces;
	server->config.queue = queue;
	server->n_threads = n_threads;
	memset(server->sessions_rx, 0, sizeof(server->sessions_rx[0])*HERCULES_CONCURRENT_SESSIONS);
	memset(server->sessions_tx, 0, sizeof(server->sessions_tx[0])*HERCULES_CONCURRENT_SESSIONS);
	server->worker_args = calloc(server->n_threads, sizeof(struct worker_args *));
	if (server->worker_args == NULL){
		exit_with_error(NULL, ENOMEM);
	}
	server->config.local_addr = local_addr;
	server->config.port_min = ntohs(local_addr.port);
	server->config.port_max = server->config.port_min + HERCULES_CONCURRENT_SESSIONS;
	server->config.configure_queues = configure_queues;
	server->config.xdp_mode = xdp_mode;
	/* server->config.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST; */
	// FIXME with flags set, setup may fail and we don't catch it?
	server->enable_pcc = enable_pcc;

	for (int i = 0; i < num_ifaces; i++) {
		server->ifaces[i] = (struct hercules_interface){
			.queue = queue,
			.ifid = ifindices[i],
			.ethtool_rule = -1,
		};
		if_indextoname(ifindices[i], server->ifaces[i].ifname);
		debug_printf("using queue %d on interface %s", server->ifaces[i].queue,
					 server->ifaces[i].ifname);
	}

	server->control_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (server->control_sockfd == -1) {
		exit_with_error(server, 0);
	}
	debug_printf("init complete");
	return server;
}

/// PACKET PARSING
// XXX: from lib/scion/udp.c
/*
 * Calculate UDP checksum
 * Same as regular IP/UDP checksum but IP addrs replaced with SCION addrs
 * buf: Pointer to start of SCION packet
 * len: Length of the upper-layer header and data
 * return value: Checksum value or 0 iff input is invalid
 */
u16 scion_udp_checksum(const u8 *buf, int len)
{
	chk_input chk_input_s;
	chk_input *input = init_chk_input(&chk_input_s, 2); // initialize checksum_parse for 2 chunks
	if(!input) {
		debug_printf("Unable to initialize checksum input: %p", input);
		return 0;
	}

	// XXX construct a pseudo header that is compatible with the checksum computation in
	// scionproto/go/lib/slayers/scion.go
	u32 pseudo_header_size = sizeof(struct scionaddrhdr_ipv4) + sizeof(struct udphdr) + 2 * sizeof(u32);
	u32 pseudo_header[pseudo_header_size / sizeof(u32)];

	// SCION address header
	const u32 *addr_hdr = (u32 *)(buf + sizeof(struct scionhdr));
	size_t i = 0;
	for(; i < sizeof(struct scionaddrhdr_ipv4) / sizeof(u32); i++) {
		pseudo_header[i] = ntohl(addr_hdr[i]);
	}
	struct scionhdr *scion_hdr = (struct scionhdr *)buf;

	pseudo_header[i++] = len;

	__u8 next_header = scion_hdr->next_header;
	size_t next_offset = scion_hdr->header_len * SCION_HEADER_LINELEN;
	if(next_header == SCION_HEADER_HBH) {
		next_header = *(buf + next_offset);
		next_offset += (*(buf + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if(next_header == SCION_HEADER_E2E) {
		next_header = *(buf + next_offset);
		next_offset += (*(buf + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}

	pseudo_header[i++] = next_header;

	// UDP header
	const u32 *udp_hdr = (const u32 *)(buf + next_offset); // skip over SCION header and extension headers
	for(int offset = i; i - offset < sizeof(struct udphdr) / sizeof(u32); i++) {
		pseudo_header[i] = ntohl(udp_hdr[i - offset]);
	}
	pseudo_header[i - 1] &= 0xFFFF0000; // zero-out UDP checksum
	chk_add_chunk(input, (u8 *)pseudo_header, pseudo_header_size);

	// Length in UDP header includes header size, so subtract it.
	struct udphdr *udphdr = (struct udphdr *)udp_hdr;
	u16 payload_len = ntohs(udphdr->len) - sizeof(struct udphdr);
	if(payload_len != len - sizeof(struct udphdr)) {
		debug_printf("Invalid payload_len: Got %u, Expected: %d", payload_len, len - (int)sizeof(struct udphdr));
		return 0;
	}
	const u8 *payload = (u8 *)(udphdr + 1); // skip over UDP header
	chk_add_chunk(input, payload, payload_len);

	u16 computed_checksum = checksum(input);
	return computed_checksum;
}

// Parse ethernet/IP/UDP/SCION/UDP packet,
// this is an extension to the parse_pkt
// function below only doing the checking
// that the BPF program has not already done.
//
// The BPF program writes the offset and the
// addr_idx to the first two words, set
// these arguments to -1 to use them.
static const char *parse_pkt_fast_path(const char *pkt, size_t length, bool check, size_t offset)
{
	if(offset == UINT32_MAX) {
		offset = *(int *)pkt;
	}
	if(check) {
		struct udphdr *l4udph = (struct udphdr *)(pkt + offset) - 1;
		u16 header_checksum = l4udph->check;
		if(header_checksum != 0) {
			// we compute these pointers here again so that we do not have to pass it from kernel space into user space
			// which could negatively affect the performance in the case when the checksum is not verified
			struct scionhdr *scionh = (struct scionhdr *)
					(pkt + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

			u16 computed_checksum = scion_udp_checksum((u8 *)scionh, length - offset + sizeof(struct udphdr));
			if(header_checksum != computed_checksum) {
				debug_printf("Checksum in SCION/UDP header %u "
				             "does not match computed checksum %u",
				             ntohs(header_checksum), ntohs(computed_checksum));
				return NULL;
			}
		}
	}
	return pkt + offset;
}

// The SCMP packet contains a copy of the offending message we sent, parse it to
// figure out which path the SCMP message is referring to.
// Returns the offending path's id, or PCC_NO_PATH on failure.
// XXX Not checking dst or source ia/addr/port in reflected packet
static u8 parse_scmp_packet(const struct scmp_message *scmp, size_t length, u16 *offending_dst_port) {
	size_t offset = 0;
	const char *pkt = NULL;
	debug_printf("SCMP type %d", scmp->type);
	switch (scmp->type) {
		case SCMP_DEST_UNREACHABLE:
		case SCMP_PKT_TOO_BIG:
		case SCMP_PARAMETER_PROBLEM:;
			pkt = (const char *)scmp->msg.err.offending_packet;
			offset += offsetof(struct scmp_message, msg.err.offending_packet);
			break;
		case SCMP_EXT_IF_DOWN:
			pkt = (const char *)scmp->msg.ext_down.offending_packet;
			offset +=
				offsetof(struct scmp_message, msg.ext_down.offending_packet);
			break;
		case SCMP_INT_CONN_DOWN:
			pkt = (const char *)scmp->msg.int_down.offending_packet;
			offset +=
				offsetof(struct scmp_message, msg.int_down.offending_packet);
			break;
		default:
			debug_printf("Unknown or unhandled SCMP type: %d", scmp->type);
			return PCC_NO_PATH;
	}
	// Parse SCION Common header
	if (offset + sizeof(struct scionhdr) > length) {
		debug_printf("too short for SCION header: %zu %zu", offset, length);
		return PCC_NO_PATH;
	}

	const struct scionhdr *scionh = (const struct scionhdr *)(pkt);
	if (scionh->version != 0u) {
		debug_printf("unsupported SCION version: %u != 0", scionh->version);
		return PCC_NO_PATH;
	}
	if (scionh->dst_type != 0u) {
		debug_printf("unsupported destination address type: %u != 0 (IPv4)",
					 scionh->dst_type);
	}
	if (scionh->src_type != 0u) {
		debug_printf("unsupported source address type: %u != 0 (IPv4)",
					 scionh->src_type);
	}

	__u8 next_header = scionh->next_header;
	size_t next_offset = offset + scionh->header_len * SCION_HEADER_LINELEN;
	if (next_header == SCION_HEADER_HBH) {
		if (next_offset + 2 > length) {
			debug_printf("too short for SCION HBH options header: %zu %zu",
						 next_offset, length);
			return PCC_NO_PATH;
		}
		next_header = *((__u8 *)pkt + next_offset);
		next_offset +=
			(*((__u8 *)pkt + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if (next_header == SCION_HEADER_E2E) {
		if (next_offset + 2 > length) {
			debug_printf("too short for SCION E2E options header: %zu %zu",
						 next_offset, length);
			return PCC_NO_PATH;
		}
		next_header = *((__u8 *)pkt + next_offset);
		next_offset +=
			(*((__u8 *)pkt + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if (next_header != IPPROTO_UDP) {
		return PCC_NO_PATH;
	}
	const struct scionaddrhdr_ipv4 *scionaddrh =
		(const struct scionaddrhdr_ipv4 *)(pkt + offset +
										   sizeof(struct scionhdr));
	offset = next_offset;

	// Finally parse the L4-UDP header
	if (offset + sizeof(struct udphdr) > length) {
		debug_printf("too short for SCION/UDP header: %zu %zu", offset, length);
		return PCC_NO_PATH;
	}

	const struct udphdr *l4udph = (const struct udphdr *)(pkt + offset);

	offset += sizeof(struct udphdr);
	const struct hercules_header *rbudp_hdr =
		(const struct hercules_header *)(pkt + offset);
	if (offending_dst_port) {
		*offending_dst_port = ntohs(l4udph->uh_dport);
	}
	return rbudp_hdr->path;
}

// Parse ethernet/IP/UDP/SCION/UDP packet,
// check that it is addressed to us,
// check SCION-UDP checksum if set.
// sets scionaddrh_o to SCION address header, if provided
// return rbudp-packet (i.e. SCION/UDP packet payload)
static const char *parse_pkt(const struct hercules_server *server,
							 const char *pkt, size_t length, bool check,
							 const struct scionaddrhdr_ipv4 **scionaddrh_o,
							 const struct udphdr **udphdr_o,
							 u8 *scmp_offending_path_o,
							 u16 *scmp_offending_dst_port_o) {
	// Parse Ethernet frame
	if(sizeof(struct ether_header) > length) {
		debug_printf("too short for eth header: %zu", length);
		return NULL;
	}
	const struct ether_header *eh = (const struct ether_header *)pkt;
	if(eh->ether_type != htons(ETHERTYPE_IP)) { // TODO: support VLAN etc?
		debug_printf("not IP");
		return NULL;
	}
	size_t offset = sizeof(struct ether_header);

	// Parse IP header
	if(offset + sizeof(struct iphdr) > length) {
		debug_printf("too short for iphdr: %zu %zu", offset, length);
		return NULL;
	}
	const struct iphdr *iph = (const struct iphdr *)(pkt + offset);
	if(iph->protocol != IPPROTO_UDP) {
		/* debug_printf("not UDP: %u, %zu", iph->protocol, offset); */
		return NULL;
	}
	if(iph->daddr != server->config.local_addr.ip) {
		/* debug_printf("not addressed to us (IP overlay)"); */
		return NULL;
	}
	offset += iph->ihl * 4u; // IHL is header length, in number of 32-bit words.

	// Parse UDP header
	if(offset + sizeof(struct udphdr) > length) {
		debug_printf("too short for udphdr: %zu %zu", offset, length);
		return NULL;
	}
	const struct udphdr *udph = (const struct udphdr *)(pkt + offset);
	if(udph->dest != htons(SCION_ENDHOST_PORT)) {
		debug_printf("not to SCION endhost port: %u", ntohs(udph->dest));
		return NULL;
	}
	offset += sizeof(struct udphdr);

	// Parse SCION Common header
	if(offset + sizeof(struct scionhdr) > length) {
		debug_printf("too short for SCION header: %zu %zu", offset, length);
		return NULL;
	}

	const struct scionhdr *scionh = (const struct scionhdr *)(pkt + offset);
	if(scionh->version != 0u) {
		debug_printf("unsupported SCION version: %u != 0", scionh->version);
		return NULL;
	}
	if(scionh->dst_type != 0u) {
		debug_printf("unsupported destination address type: %u != 0 (IPv4)", scionh->dst_type);
	}
	if(scionh->src_type != 0u) {
		debug_printf("unsupported source address type: %u != 0 (IPv4)", scionh->src_type);
	}

	__u8 next_header = scionh->next_header;
	size_t next_offset = offset + scionh->header_len * SCION_HEADER_LINELEN;
	if(next_header == SCION_HEADER_HBH) {
		if(next_offset + 2 > length) {
			debug_printf("too short for SCION HBH options header: %zu %zu", next_offset, length);
			return NULL;
		}
		next_header = *((__u8 *)pkt + next_offset);
		next_offset += (*((__u8 *)pkt + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if(next_header == SCION_HEADER_E2E) {
		if(next_offset + 2 > length) {
			debug_printf("too short for SCION E2E options header: %zu %zu", next_offset, length);
			return NULL;
		}
		next_header = *((__u8 *)pkt + next_offset);
		next_offset += (*((__u8 *)pkt + next_offset + 1) + 1) * SCION_HEADER_LINELEN;
	}
	if(next_header != IPPROTO_UDP) {
		if (next_header == L4_SCMP) {
			if (next_offset + sizeof(struct scmp_message) > length) {
				debug_printf("SCMP, too short?");
				return NULL;
			}
			const struct scmp_message *scmp_msg =
				(const struct scmp_message *)(pkt + next_offset);
			*scmp_offending_path_o =
				parse_scmp_packet(scmp_msg, length - next_offset, scmp_offending_dst_port_o);
		} else {
			debug_printf("unknown SCION L4: %u", next_header);
		}
		return NULL;
	}
	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *)(pkt + offset +
	                                                                                sizeof(struct scionhdr));
	if(scionaddrh->dst_ia != server->config.local_addr.ia) {
		debug_printf("not addressed to us (IA): expect %llx, have %llx", server->config.local_addr.ia, scionaddrh->dst_ia);
		return NULL;
	}
	if(scionaddrh->dst_ip != server->config.local_addr.ip) {
		debug_printf("not addressed to us (IP in SCION hdr), expect %x, have %x, remote %x",
		             server->config.local_addr.ip, scionaddrh->dst_ip, 0xFF);
		return NULL;
	}

	offset = next_offset;

	// Finally parse the L4-UDP header
	if(offset + sizeof(struct udphdr) > length) {
		debug_printf("too short for SCION/UDP header: %zu %zu", offset, length);
		return NULL;
	}

	const struct udphdr *l4udph = (const struct udphdr *)(pkt + offset);
	if (ntohs(l4udph->dest) < server->config.port_min ||
		ntohs(l4udph->dest) > server->config.port_max) {
		debug_printf("not addressed to us (L4 UDP port): %u",
					 ntohs(l4udph->dest));
		return NULL;
	}

	offset += sizeof(struct udphdr);
	if(scionaddrh_o != NULL) {
		*scionaddrh_o = scionaddrh;
	}
	if(udphdr_o != NULL) {
		*udphdr_o = l4udph;
	}
	return parse_pkt_fast_path(pkt, length, check, offset);
}

static inline void stitch_src_port(const struct hercules_path *path, u16 port, char *pkt){
	char *payload = pkt + path->headerlen;
	u16 *udp_src = (u16 *)(payload-8);
	*udp_src = htons(port);
}

static inline void stitch_dst_port(const struct hercules_path *path, u16 port, char *pkt){
	char *payload = pkt + path->headerlen;
	u16 *udp_dst = (u16 *)(payload-6);
	*udp_dst = htons(port);
}

static void stitch_checksum_with_dst(const struct hercules_path *path, u16 precomputed_checksum, char *pkt)
{
	chk_input chk_input_s;
	chk_input *chksum_struc = init_chk_input(&chk_input_s, 4);
	assert(chksum_struc);
	char *payload = pkt + path->headerlen;
	u16 udp_src_le = ntohs(*(u16*)(payload - 8)); // Why in host order?
	u16 udp_dst_le = ntohs(*(u16*)(payload - 6));
	precomputed_checksum = ~precomputed_checksum; // take one complement of precomputed checksum
	chk_add_chunk(chksum_struc, (u8 *)&precomputed_checksum, 2); // add precomputed header checksum
	chk_add_chunk(chksum_struc, (u8 *)&udp_src_le, 2);
	chk_add_chunk(chksum_struc, (u8 *)&udp_dst_le, 2);
	chk_add_chunk(chksum_struc, (u8 *)payload, path->payloadlen); // add payload
	u16 pkt_checksum = checksum(chksum_struc);

	mempcpy(payload - 2, &pkt_checksum, sizeof(pkt_checksum));
}

static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt)
{
	chk_input chk_input_s;
	chk_input *chksum_struc = init_chk_input(&chk_input_s, 3);
	assert(chksum_struc);
	char *payload = pkt + path->headerlen;
	u16 udp_src_le = ntohs(*(u16*)(payload - 8)); // Why in host order?
	precomputed_checksum = ~precomputed_checksum; // take one complement of precomputed checksum
	chk_add_chunk(chksum_struc, (u8 *)&precomputed_checksum, 2); // add precomputed header checksum
	chk_add_chunk(chksum_struc, (u8 *)&udp_src_le, 2);
	chk_add_chunk(chksum_struc, (u8 *)payload, path->payloadlen); // add payload
	u16 pkt_checksum = checksum(chksum_struc);

	mempcpy(payload - 2, &pkt_checksum, sizeof(pkt_checksum));
}

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx, u8 flags,
						   sequence_number seqnr, const char *data, size_t n,
						   size_t payloadlen) {
	struct hercules_header *hdr = (struct hercules_header *)rbudp_pkt;
	hdr->chunk_idx = chunk_idx;
	hdr->path = path_idx;
	hdr->flags = flags;
	hdr->seqno = seqnr;
	void *start_pad = mempcpy(hdr->data, data, n);
	if (rbudp_headerlen + n < payloadlen) {
		memset(start_pad, 0,
			   payloadlen - rbudp_headerlen - n);
	}
	debug_print_rbudp_pkt(rbudp_pkt, false);
}

// Check an initial (HS) packet and return a pointer to it in *parsed_pkt
static bool rbudp_check_initial(struct hercules_control_packet *pkt, size_t len, struct rbudp_initial_pkt **parsed_pkt)
{
	if(pkt->type != CONTROL_PACKET_TYPE_INITIAL) {
		debug_printf("Packet type not INITIAL");
		return false;
	}
	if(len < sizeof(pkt->type) + sizeof(*parsed_pkt)) {
		debug_printf("Packet too short");
		return false;
	}
	*parsed_pkt = &pkt->payload.initial;
	return true;
}

// Load the pathset currently in use and publish its epoch so the freeing thread
// knows when it's safe to free
static struct path_set *pathset_read(struct sender_state *tx_state, u32 id) {
	struct path_set *pathset = atomic_load(&tx_state->pathset);
	atomic_store(&tx_state->epochs[id].epoch, pathset->epoch);
	return pathset;
}

/// RECEIVER

static bool rx_received_all(const struct receiver_state *rx_state,
							const bool is_index_transfer) {
	if (is_index_transfer) {
		return (rx_state->received_chunks_index.num_set ==
				rx_state->index_chunks);
	}
	return (rx_state->received_chunks.num_set == rx_state->total_chunks);
}

static bool handle_rbudp_data_pkt(struct receiver_state *rx_state, const char *pkt, size_t length)
{
	if(length < rbudp_headerlen + rx_state->chunklen) {
		debug_printf("packet too short: have %lu, expect %d", length, rbudp_headerlen + rx_state->chunklen );
		return false;
	}

	struct hercules_header *hdr = (struct hercules_header *)pkt;
	bool is_index_transfer = hdr->flags & PKT_FLAG_IS_INDEX;

	u32 chunk_idx = hdr->chunk_idx;
	if (is_index_transfer) {
		if (chunk_idx >= rx_state->index_chunks) {
			if (chunk_idx == UINT_MAX) {
				// control packet is handled elsewhere
			} else {
				fprintf(stderr,
						"ERROR: IDX chunk_idx larger than expected: %u >= %u\n",
						chunk_idx, rx_state->index_chunks);
			}
			return false;
		}
	} else {
		if (chunk_idx >= rx_state->total_chunks) {
			if (chunk_idx == UINT_MAX) {
				// control packet is handled elsewhere
			} else {
				fprintf(stderr,
						"ERROR: DATA chunk_idx larger than expected: %u >= %u\n",
						chunk_idx, rx_state->total_chunks);
			}
			return false;
		}
	}

	u8 path_idx = hdr->path;
	if(path_idx < PCC_NO_PATH) {
		sequence_number seqnr = hdr->seqno;
		if(rx_state->path_state[path_idx].seq_rcvd.bitmap == NULL) {
                  // TODO compute correct number here
			bitset__create(&rx_state->path_state[path_idx].seq_rcvd, 200 * rx_state->total_chunks);
			// TODO work out wrap-around
		}
		if(seqnr >= rx_state->path_state[path_idx].seq_rcvd.num) {
			// XXX: currently we cannot track these sequence numbers, as a consequence congestion control breaks at this
			// point, abort.
			if(!session_state_is_running(rx_state->session->state)) {
				return true;
			} else {
				fprintf(stderr, "sequence number overflow %d / %d\n", seqnr,
				        rx_state->path_state[path_idx].seq_rcvd.num);
				quit_session(rx_state->session, SESSION_ERROR_SEQNO_OVERFLOW);
				return false;
			}
		}
		bitset__set_mt_safe(&rx_state->path_state[path_idx].seq_rcvd, seqnr);

		u8 old_num = atomic_load(&rx_state->num_tracked_paths);
		while(old_num < path_idx + 1) { // update num_tracked_paths
			atomic_compare_exchange_strong(&rx_state->num_tracked_paths, &old_num, path_idx + 1);
		}
		atomic_fetch_add(&rx_state->path_state[path_idx].rx_npkts, 1);
	}
	bool prev;
	if(rx_state->is_pcc_benchmark) {
		prev = false; // for benchmarking, we did "not receive this packet before"
		// this wilrcl trick the sender into sending the file over and over again,
		// regardless of which packets have actually been received. This does not
		// break PCC because that takes NACKs send on a per-path basis as feedback
	} else {
		// mark as received in received_chunks bitmap
		if (is_index_transfer) {
			prev = bitset__set_mt_safe(&rx_state->received_chunks_index,
									   chunk_idx);
		} else {
			prev = bitset__set_mt_safe(&rx_state->received_chunks, chunk_idx);
		}
	}
	if(!prev) {
		char *target_ptr = rx_state->mem;
		const char *payload = pkt + rbudp_headerlen;
		const size_t chunk_start = (size_t)chunk_idx * rx_state->chunklen;
		size_t len =
			umin64(rx_state->chunklen, rx_state->filesize - chunk_start);
		if (is_index_transfer) {
			target_ptr = rx_state->index;
			len = umin64(rx_state->chunklen, rx_state->index_size - chunk_start);
		}
		memcpy(target_ptr + chunk_start, payload, len);
		// Update last new pkt timestamp
		atomic_store(&rx_state->session->last_new_pkt_rcvd, get_nsecs());
	}
	return true;
}

static u32 fill_ack_pkt(struct receiver_state *rx_state, u32 first, struct rbudp_ack_pkt *ack, size_t max_num_acks, bool is_index_transfer)
{
	size_t e = 0;
	u32 curr = first;
	struct bitset *set = &rx_state->received_chunks;
	u32 num = rx_state->received_chunks.num;
	if (is_index_transfer){
		set = &rx_state->received_chunks_index;
		num = rx_state->received_chunks_index.num;
	}
	for(; e < max_num_acks;) {
		u32 begin = bitset__scan(set, curr);
		if(begin == num) {
			curr = begin;
			break;
		}
		u32 end = bitset__scan_neg(set, begin + 1);
		curr = end + 1;
		ack->acks[e].begin = begin;
		ack->acks[e].end = end;
		e++;
	}
	ack->num_acks = e;
	return curr;
}

static sequence_number
fill_nack_pkt(sequence_number first, struct rbudp_ack_pkt *ack, size_t max_num_acks, struct bitset *seqs)
{
	size_t e = 0;
	u32 curr = first;
	for(; e < max_num_acks;) {
		u32 begin = bitset__scan_neg(seqs, curr);
		u32 end = bitset__scan(seqs, begin + 1);
		if(end == seqs->num) {
			break;
		}
		curr = end + 1;
		ack->acks[e].begin = begin;
		ack->acks[e].end = end;
		e++;
	}
	ack->num_acks = e;
	return curr;
}

static bool has_more_nacks(sequence_number curr, struct bitset *seqs)
{
	u32 begin = bitset__scan_neg(seqs, curr);
	u32 end = bitset__scan(seqs, begin + 1);
	return end < seqs->num;
}

static void
submit_rx_frames(struct xsk_umem_info *umem, const u64 *addrs, size_t num_frames)
{
	u32 idx_fq = 0;
	pthread_spin_lock(&umem->fq_lock);
	size_t reserved = xsk_ring_prod__reserve(&umem->fq, num_frames, &idx_fq);
	while(reserved != num_frames) {
		reserved = xsk_ring_prod__reserve(&umem->fq, num_frames, &idx_fq);
        // FIXME this
		/* if(session == NULL || session->state != SESSION_STATE_RUNNING) { */
		/* 	pthread_spin_unlock(&umem->fq_lock); */
		/* 	return; */
		/* } */
	}

	for(size_t i = 0; i < num_frames; i++) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) = addrs[i];
	}
	xsk_ring_prod__submit(&umem->fq, num_frames);
	pthread_spin_unlock(&umem->fq_lock);
}

// Read a batch of data packets from the XSK
static void rx_receive_batch(struct hercules_server *server,
							 struct xsk_socket_info *xsk) {
	u32 idx_rx = 0;
	int ignored = 0;

	size_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if (!rcvd) {
		return;
	}

	// optimistically update receive timestamp

	u64 frame_addrs[BATCH_SIZE];
	for (size_t i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
		frame_addrs[i] = addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
		const char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		const char *rbudp_pkt = parse_pkt_fast_path(pkt, len, true, UINT32_MAX);
		u16 pkt_dst_port = ntohs(*(u16 *)(rbudp_pkt - 6));
		struct hercules_session *session_rx = lookup_session_rx(server, pkt_dst_port);
		if (session_rx == NULL || !session_state_is_running(session_rx->state)){
			continue;
		}
		u64 now = get_nsecs();
		u64 old_last_pkt_rcvd = atomic_load(&session_rx->rx_state->last_pkt_rcvd);
		if (old_last_pkt_rcvd < now) {
			atomic_compare_exchange_strong(&session_rx->rx_state->last_pkt_rcvd,
										   &old_last_pkt_rcvd, now);
		}
		atomic_store(&session_rx->last_pkt_rcvd, now);
		if (rbudp_pkt) {
			debug_print_rbudp_pkt(rbudp_pkt, true);
			if (!handle_rbudp_data_pkt(session_rx->rx_state, rbudp_pkt,
									   len - (rbudp_pkt - pkt))) {
				debug_printf("Non-data packet on XDP socket? Ignoring.");
			}
		} else {
			debug_printf("Unparseable packet on XDP socket, ignoring");
		}
		atomic_fetch_add(&session_rx->rx_npkts, 1);

	}
	xsk_ring_cons__release(&xsk->rx, rcvd);
	submit_rx_frames(xsk->umem, frame_addrs, rcvd);
}

// Prepare a file and memory mapping to receive a file
static char *rx_mmap(const char *index, size_t index_size, size_t total_filesize) {
	debug_printf("total filesize %ld", total_filesize);
	debug_printf("total entry size %ld", index_size);
	char *mem = mmap(NULL, total_filesize, PROT_READ, MAP_PRIVATE | MAP_ANON, 0, 0);
	if (mem == MAP_FAILED) {
		return NULL;
	}
	char *next_mapping = mem;

	struct dir_index_entry *p = (struct dir_index_entry *)index;
	while (1) {
		debug_printf("Read: %s (%d) %dB", p->path, p->type, p->filesize);
		int ret;
		if (p->type == INDEX_TYPE_FILE) {
			int f = open(p->path, O_RDWR | O_CREAT | O_EXCL, 0664);
			if (f == -1 && errno == EEXIST) {
				f = open(p->path, O_RDWR | O_EXCL);
			}
			if (f == -1) {
				return NULL;
			}
			ret =
				fallocate(f, 0, 0,
						  p->filesize);	 // Will fail on old filesystems (ext3)
			if (ret) {
				close(f);
				return NULL;
			}
			debug_printf("%p: %s", next_mapping, p->path);
			char *filemap = mmap(next_mapping, p->filesize, PROT_WRITE,
								 MAP_SHARED | MAP_FIXED, f, 0);
			debug_printf("%p: %d", filemap, filemap == next_mapping);
			if (filemap == MAP_FAILED) {
				debug_printf("filemap err!");
				return NULL;
			}
				u32 filesize_up =
					((4096 - 1) & p->filesize)
						? ((p->filesize + 4096) & ~(4096 - 1))
						: p->filesize;
			next_mapping += filesize_up;
			close(f);
		}
		else if (p->type == INDEX_TYPE_DIR){
			ret = mkdir(p->path, 0664);
			if (ret != 0) {
				// XXX should an already existing directory be an error?
				if (errno == EEXIST) {
					struct stat statbuf;
					stat(p->path, &statbuf);
					if (!S_ISDIR(statbuf.st_mode)){
						debug_printf("path exists but is not a directory?");
						return NULL;
					}
				} else {
					debug_printf("mkdir err");
					return NULL;
				}
			}
		}
		p = ((char *)p) + sizeof(*p) + p->path_len;
		if (p >= index + index_size) {
			break;
		}
	}
	return mem;
}

// Create new receiver state. Returns null in case of error.
static struct receiver_state *make_rx_state(struct hercules_session *session,
											char *index, size_t index_size,
											size_t filesize, int chunklen,
											u16 src_port,
											bool is_pcc_benchmark) {
	struct receiver_state *rx_state;
	rx_state = calloc(1, sizeof(*rx_state));
	if (rx_state == NULL){
		return NULL;
	}
	rx_state->session = session;
	rx_state->filesize = filesize;
	rx_state->chunklen = chunklen;
	rx_state->total_chunks = (filesize + chunklen - 1) / chunklen;
	bitset__create(&rx_state->received_chunks, rx_state->total_chunks);
	rx_state->start_time = 0;
	rx_state->end_time = 0;
	rx_state->handshake_rtt = 0;
	rx_state->is_pcc_benchmark = is_pcc_benchmark;
	rx_state->mem = rx_mmap(index, index_size, filesize);
	rx_state->src_port = src_port;
	if (rx_state->mem == NULL) {
		free(rx_state);
		return NULL;
	}
	return rx_state;
}

// For index transfer: Create new receiver state without mapping a file. Returns
// null in case of error.
static struct receiver_state *make_rx_state_nomap(
	struct hercules_session *session, size_t index_size,
	size_t filesize, int chunklen, u16 src_port, bool is_pcc_benchmark) {
	struct receiver_state *rx_state;
	rx_state = calloc(1, sizeof(*rx_state));
	if (rx_state == NULL) {
		return NULL;
	}
	rx_state->session = session;
	rx_state->filesize = filesize;
	rx_state->chunklen = chunklen;
	rx_state->total_chunks = (filesize + chunklen - 1) / chunklen;
	rx_state->index_chunks = (index_size + chunklen - 1) / chunklen;
	bitset__create(&rx_state->received_chunks, rx_state->total_chunks);
	bitset__create(&rx_state->received_chunks_index, rx_state->index_chunks);
	rx_state->start_time = 0;
	rx_state->end_time = 0;
	rx_state->handshake_rtt = 0;
	rx_state->src_port = src_port;
	rx_state->is_pcc_benchmark = is_pcc_benchmark;
	// XXX We cannot map the file(s) yet since we don't have the index,
	// but we could already reserve the required range (to check if there's even
	// enough memory available)
	return rx_state;
}

// Update the reply path using the header from a received packet.
// The packet is sent to the monitor, which will return a new header with the
// path reversed.
static bool rx_update_reply_path(
	struct hercules_server *server, struct receiver_state *rx_state, int ifid,
	int etherlen,
	int rx_sample_len, const char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE]) {
	debug_printf("Updating reply path");
	if (!rx_state) {
		debug_printf("ERROR: invalid rx_state");
		return false;
	}
	assert(rx_sample_len > 0);
	assert(rx_sample_len <= XSK_UMEM__DEFAULT_FRAME_SIZE);

	// TODO writing to reply path needs sync?
	int ret =
		monitor_get_reply_path(server->usock, rx_sample_buf, rx_sample_len,
							   etherlen, &rx_state->reply_path);
	if (!ret) {
		return false;
	}
	// XXX Do we always want to reply from the interface the packet was received
	// on?
	// TODO The monitor also returns an interface id (from route lookup)
	rx_state->reply_path.ifid = ifid;
	return true;
}

// Return a copy of the currently stored reply path.
static bool rx_get_reply_path(struct receiver_state *rx_state,
							  struct hercules_path *path) {
	memcpy(path, &rx_state->reply_path, sizeof(*path));
	return true;
}

// Reflect the received initial packet back to the sender. The sent packet is
// identical to the one received, but has the HS_CONFIRM flag set.
static void rx_send_rtt_ack(struct hercules_server *server,
							struct receiver_state *rx_state, int rx_slot,
							struct rbudp_initial_pkt *pld) {
	struct hercules_path path;
	if(!rx_get_reply_path(rx_state, &path)) {
		debug_printf("no return path");
		return;
	}

	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path.header.header, path.headerlen);

	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_INITIAL,
			.payload.initial = *pld,
	};
	control_pkt.payload.initial.flags |= HANDSHAKE_FLAG_HS_CONFIRM;

	stitch_src_port(&path, server->config.port_min + rx_slot + 1, buf);
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, 0, (char *)&control_pkt,
	               sizeof(control_pkt.type) + sizeof(control_pkt.payload.initial), path.payloadlen);
	stitch_checksum(&path, path.header.checksum, buf);

	send_eth_frame(server, &path, buf);
	atomic_fetch_add(&rx_state->session->tx_npkts, 1);
}

// Handle a received HS packet by reflecting it back to its sender and update
// the session's reply path if the corresponding flag was set
static void rx_handle_initial(struct hercules_server *server,
							  struct receiver_state *rx_state,
							  struct rbudp_initial_pkt *initial, int rx_slot,
							  const char *buf, int ifid, const char *payload,
							  int framelen) {
	debug_printf("handling initial");
	// Payload points to the rbudp payload (after the rbudp header)
	const int headerlen = (int)(payload - buf); // Length of ALL headers (including rbudp)
	if (initial->flags & HANDSHAKE_FLAG_SET_RETURN_PATH) {
		debug_printf("initial headerlen, framelen: %d, %d", headerlen, framelen);
		debug_printf("initial chunklen: %d", initial->chunklen);
		// XXX Why use both initial->chunklen (transmitted) and the size of the received packet?
		// Are they ever not the same?
		rx_update_reply_path(server, rx_state, ifid, initial->chunklen + headerlen, framelen, buf);
	}
	rx_send_rtt_ack(server, rx_state, rx_slot,
					initial);  // echo back initial pkt to ACK filesize
}

// Send an empty ACK, indicating to the sender that it may start sending data
// packets.
// This is not strictly necessary. Once the ACK sender thread sees
// the session it will start sending ACKs, which will also be empty.
static void rx_send_cts_ack(struct hercules_server *server,
							struct receiver_state *rx_state) {
	debug_printf("Send CTS ACK");
	struct hercules_path path;
	if(!rx_get_reply_path(rx_state, &path)) {
		debug_printf("no reply path");
		return;
	}

	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path.header.header, path.headerlen);

	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_ACK,
			.payload.ack.num_acks = 0,
	};

	stitch_src_port(&path, rx_state->src_port, buf);
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, 0, (char *)&control_pkt,
	               sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
	stitch_checksum(&path, path.header.checksum, buf);
	send_eth_frame(server, &path, buf);
	atomic_fetch_add(&rx_state->session->tx_npkts, 1);
}

// TODO some other functions repeat this code
// Send the given control packet via the server's control socket.
static void send_control_pkt(struct hercules_server *server,
							 struct hercules_session *session,
							 struct hercules_control_packet *control_pkt,
							 struct hercules_path *path,
                             u16 src_port,
							 bool is_index_transfer) {
	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path->header.header, path->headerlen);

	u8 flag = 0;
	if (is_index_transfer) {
		flag |= PKT_FLAG_IS_INDEX;
	}
	stitch_src_port(path, src_port, buf);
	fill_rbudp_pkt(
		rbudp_pkt, UINT_MAX, PCC_NO_PATH, flag, 0, (char *)control_pkt,
		sizeof(control_pkt->type) + ack__len(&control_pkt->payload.ack),
		path->payloadlen);
	stitch_checksum(path, path->header.checksum, buf);

	send_eth_frame(server, path, buf);
	atomic_fetch_add(&session->tx_npkts, 1);
}

// Send as many ACK packets as necessary to convey all received packet ranges
static void rx_send_acks(struct hercules_server *server, struct receiver_state *rx_state, bool is_index_transfer)
{
	struct hercules_path path;
	if(!rx_get_reply_path(rx_state, &path)) {
		debug_printf("no reply path");
		return;
	}
	// XXX: could write ack payload directly to buf, but
	// doesnt work nicely with existing fill_rbudp_pkt helper.
	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_ACK,
	};

	const size_t max_entries = ack__max_num_entries(path.payloadlen - rbudp_headerlen - sizeof(control_pkt.type));

	// send an empty ACK to keep connection alive until first packet arrives
	u32 curr = fill_ack_pkt(rx_state, 0, &control_pkt.payload.ack, max_entries, is_index_transfer);
	send_control_pkt(server, rx_state->session, &control_pkt, &path, rx_state->src_port, is_index_transfer);
	for(; curr < rx_state->total_chunks;) {
		curr = fill_ack_pkt(rx_state, curr, &control_pkt.payload.ack, max_entries, is_index_transfer);
		if(control_pkt.payload.ack.num_acks == 0) break;
		send_control_pkt(server, rx_state->session, &control_pkt, &path, rx_state->src_port, is_index_transfer);
	}
}


static void rx_send_path_nacks(struct hercules_server *server, struct receiver_state *rx_state, struct receiver_state_per_path *path_state, u8 path_idx, u64 time, u32 nr, bool is_index_transfer)
{
	struct hercules_path path;
	if(!rx_get_reply_path(rx_state, &path)) {
		debug_printf("no reply path");
		return;
	}

	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path.header.header, path.headerlen);

	// XXX: could write ack payload directly to buf, but
	// doesnt work nicely with existing fill_rbudp_pkt helper.
	struct hercules_control_packet control_pkt = {
			.type = CONTROL_PACKET_TYPE_NACK,
	};
	const size_t max_entries = ack__max_num_entries(path.payloadlen - rbudp_headerlen - sizeof(control_pkt.type));
	sequence_number nack_end = path_state->nack_end;
	//sequence_number start = nack_end;
	bool sent = false;
	pthread_spin_lock(&path_state->seq_rcvd.lock);
	libbpf_smp_rmb();
	for(u32 curr = path_state->nack_end; curr < path_state->seq_rcvd.num;) {
		// Data to send
		curr = fill_nack_pkt(curr, &control_pkt.payload.ack, max_entries, &path_state->seq_rcvd);
		if(has_more_nacks(curr, &path_state->seq_rcvd)) {
			control_pkt.payload.ack.max_seq = 0;
		} else {
			control_pkt.payload.ack.max_seq = path_state->seq_rcvd.max_set;
		}
		if(control_pkt.payload.ack.num_acks == 0 && sent) break;
		sent = true; // send at least one packet each round

		control_pkt.payload.ack.ack_nr = nr;
		control_pkt.payload.ack.timestamp = time;

		if(control_pkt.payload.ack.num_acks != 0) {
			nack_end = control_pkt.payload.ack.acks[control_pkt.payload.ack.num_acks - 1].end;
		}
		u8 flag = 0;
		if (is_index_transfer) {
			flag |= PKT_FLAG_IS_INDEX;
		}
		stitch_src_port(&path, rx_state->src_port, buf);
		fill_rbudp_pkt(rbudp_pkt, UINT_MAX, path_idx, flag, 0, (char *)&control_pkt,
		               sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
		stitch_checksum(&path, path.header.checksum, buf);

		send_eth_frame(server, &path, buf);
		atomic_fetch_add(&rx_state->session->tx_npkts, 1);
	}
	libbpf_smp_wmb();
	pthread_spin_unlock(&path_state->seq_rcvd.lock);
	path_state->nack_end = nack_end;
}

// sends the NACKs used for congestion control by the sender
static void rx_send_nacks(struct hercules_server *server, struct receiver_state *rx_state, u64 time, u32 nr, bool is_index_transfer)
{
	u8 num_paths = atomic_load(&rx_state->num_tracked_paths);
	for(u8 p = 0; p < num_paths; p++) {
		rx_send_path_nacks(server, rx_state, &rx_state->path_state[p], p, time, nr, is_index_transfer);
	}
}

/// SENDER
static bool tx_acked_all(const struct sender_state *tx_state) {
	if (tx_state->acked_chunks.num_set != tx_state->total_chunks) {
		return false;
	}
	return true;
}

static bool tx_acked_all_index(const struct sender_state *tx_state) {
	if (tx_state->acked_chunks_index.num_set != tx_state->index_chunks) {
		return false;
	}
	return true;
}

// Submitting the frames to the TX ring does not mean they will be sent immediately,
// this forces all submitted packets to be sent so we can get the frames back
static void kick_tx(struct hercules_server *server, struct xsk_socket_info *xsk)
{
	int ret;
	do {
		ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	} while(ret < 0 && errno == EAGAIN);

	if(ret < 0 && errno != ENOBUFS && errno != EBUSY) {
		exit_with_error(server, errno);
	}
}

static void kick_all_tx(struct hercules_server *server, struct hercules_interface *iface)
{
	for(u32 s = 0; s < iface->num_sockets; s++) {
		kick_tx(server, iface->xsks[s]);
	}
}

static void kick_tx_server(struct hercules_server *server){

	for (int i = 0; i < server->num_ifaces; i++){
		kick_all_tx(server, &server->ifaces[i]);
	}
}

static void tx_register_acks(const struct rbudp_ack_pkt *ack, struct sender_state *tx_state)
{
	for(uint16_t e = 0; e < ack->num_acks; ++e) {
		const u32 begin = ack->acks[e].begin;
		const u32 end = ack->acks[e].end;
		if(begin >= end || end > tx_state->acked_chunks.num) {
			return; // Abort
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&tx_state->acked_chunks, i); // don't need thread-safety here, all updates in same thread
		}
	}
}

static void tx_register_acks_index(const struct rbudp_ack_pkt *ack, struct sender_state *tx_state)
{
	for(uint16_t e = 0; e < ack->num_acks; ++e) {
		const u32 begin = ack->acks[e].begin;
		const u32 end = ack->acks[e].end;
		if(begin >= end || end > tx_state->acked_chunks_index.num) {
			return; // Abort
		}
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&tx_state->acked_chunks_index, i); // don't need thread-safety here, all updates in same thread
		}
	}
}

// Pop entries from completion ring and store them in umem->available_frames.
static void pop_completion_ring(struct hercules_server *server, struct xsk_umem_info *umem)
{
	u32 idx;
	size_t entries = xsk_ring_cons__peek(&umem->cq, SIZE_MAX, &idx);
	if(entries > 0) {
		u16 num = frame_queue__prod_reserve(&umem->available_frames, entries);
		if(num < entries) { // there are less frames in the loop than the number of slots in frame_queue
			debug_printf("trying to push %ld frames, only got %d slots in frame_queue", entries, num);
			exit_with_error(server, EINVAL);
		}
		for(u16 i = 0; i < num; i++) {
			frame_queue__prod_fill(&umem->available_frames, i, *xsk_ring_cons__comp_addr(&umem->cq, idx + i));
		}
		frame_queue__push(&umem->available_frames, num);
		xsk_ring_cons__release(&umem->cq, entries);
	}
}

static inline void pop_completion_rings(struct hercules_server *server)
{
	for(int i = 0; i < server->num_ifaces; i++) {
		pop_completion_ring(server, server->ifaces[i].umem);
	}
}

static void tx_register_nacks(const struct rbudp_ack_pkt *nack, struct ccontrol_state *cc_state)
{
	pthread_spin_lock(&cc_state->lock);
	atomic_store(&cc_state->mi_seq_max, umax32(atomic_load(&cc_state->mi_seq_max), nack->max_seq));
	cc_state->num_nack_pkts++;
	u32 counted = 0;
	for(uint16_t e = 0; e < nack->num_acks; ++e) {
		u32 begin = nack->acks[e].begin;
		u32 end = nack->acks[e].end;
		cc_state->mi_seq_min = umin32(cc_state->mi_seq_min, begin);
		atomic_store(&cc_state->mi_seq_max_rcvd, umax32(atomic_load(&cc_state->mi_seq_max_rcvd), end));
		begin = umax32(begin, cc_state->mi_seq_start);
		u32 seq_end = atomic_load(&cc_state->mi_seq_end);
		if(seq_end != 0) {
			end = umin32(end, seq_end);
		}
		if(begin >= end) {
			continue;
		}
		counted += end - begin;
		cc_state->num_nacks += end - begin;
		begin -= cc_state->mi_seq_start;
		end -= cc_state->mi_seq_start;
		if(end >= cc_state->mi_nacked.num) {
			fprintf(stderr, "Cannot track NACK! Out of range: nack end = %d >= bitset size %d\n", end, cc_state->mi_nacked.num);
		}
		end = umin32(end, cc_state->mi_nacked.num);
		for(u32 i = begin; i < end; ++i) { // XXX: this can *obviously* be optimized
			bitset__set(&cc_state->mi_nacked, i); // don't need thread-safety here, all updates in same thread
		}
	}
	pthread_spin_unlock(&cc_state->lock);
}


static void
tx_send_initial(struct hercules_server *server, const struct hercules_path *path, void *index, u64 index_size, int tx_slot, u16 dst_port, size_t filesize, u32 chunklen, unsigned long timestamp, u32 path_index, bool set_return_path, bool new_transfer)
{
	debug_printf("Sending initial");
	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path->header.header, path->headerlen);

	u8 flags = 0;
	if (set_return_path){
		flags |= HANDSHAKE_FLAG_SET_RETURN_PATH;
	}
	if (new_transfer){
		flags |= HANDSHAKE_FLAG_NEW_TRANSFER;
	}

	struct hercules_control_packet pld = {
		.type = CONTROL_PACKET_TYPE_INITIAL,
		.payload.initial =
			{
				.filesize = filesize,
				.chunklen = chunklen,
				.timestamp = timestamp,
				.path_index = path_index,
				.flags = flags,
				.index_len = index_size,
			},
	};
	// Using sizeof(pld) would give fewer bytes than actually available due
	// to the union in struct hercules_control_packet
	u64 initial_pl_size = sizeof(pld.type) + sizeof(pld.payload.initial);

	// Only include directory index in the very first HS packet
	if (new_transfer) {
		u64 index_bytes_available = path->payloadlen - initial_pl_size;

		debug_printf("bytes for index: %lld, size %lld", index_bytes_available,
					 index_size);
		if (index_size > index_bytes_available) {
			// Index won't fit, will be transferred separately
			debug_printf("index too long for HS packet!");
			pld.payload.initial.flags |= HANDSHAKE_FLAG_INDEX_FOLLOWS;
		} else {
			// Index is small enough to fit in the HS packet, include it
			debug_printf("Index contained in HS packet");
			memcpy(pld.payload.initial.index, index, index_size);
			initial_pl_size += index_size;
		}
	}
	stitch_src_port(path, server->config.port_min + tx_slot + 1, buf);
	stitch_dst_port(path, dst_port, buf);
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, 0, (char *)&pld,
				   initial_pl_size, path->payloadlen);
	stitch_checksum_with_dst(path, path->header.checksum, buf);

	send_eth_frame(server, path, buf);
	atomic_fetch_add(&server->sessions_tx[tx_slot]->tx_npkts, 1);
}

// TODO do something instead of spinning until time is up
static void rate_limit_tx(struct sender_state *tx_state)
{
	if(tx_state->prev_tx_npkts_queued + RATE_LIMIT_CHECK > tx_state->tx_npkts_queued)
		return;

	u64 now = get_nsecs();
	u64 dt = now - tx_state->prev_rate_check;

	u64 d_npkts = tx_state->tx_npkts_queued - tx_state->prev_tx_npkts_queued;

	dt = umin64(dt, 1);
	u32 tx_pps = d_npkts * 1.e9 / dt;

	if(tx_pps > tx_state->rate_limit) {
		u64 min_dt = (d_npkts * 1.e9 / tx_state->rate_limit);

		// Busy wait implementation
		while(now < tx_state->prev_rate_check + min_dt) {
			now = get_nsecs();
		}
	}

	tx_state->prev_rate_check = now;
	tx_state->prev_tx_npkts_queued = tx_state->tx_npkts_queued;
}

void send_path_handshakes(struct hercules_server *server,
						  struct sender_state *tx_state,
						  int tx_slot,
						  struct path_set *pathset) {
	u64 now = get_nsecs();
	for (u32 p = 0; p < pathset->n_paths; p++) {
		struct hercules_path *path = &pathset->paths[p];
		if (path->enabled) {
			u64 handshake_at = atomic_load(&path->next_handshake_at);
			if (handshake_at < now) {
				if (atomic_compare_exchange_strong(
						&path->next_handshake_at, &handshake_at,
						now + PATH_HANDSHAKE_TIMEOUT_NS)) {
					debug_printf("sending hs on path %d", p);
					// FIXME file name below?
					tx_send_initial(server, path, NULL, 0, tx_slot, tx_state->session->dst_port, tx_state->filesize,
									tx_state->chunklen, get_nsecs(), p, false,
									false);
				}
			}
		}
	}
}

static void claim_tx_frames(struct hercules_server *server, struct hercules_session *session, struct hercules_interface *iface, u64 *addrs, size_t num_frames)
{
	pthread_spin_lock(&iface->umem->frames_lock);
	size_t reserved = frame_queue__cons_reserve(&iface->umem->available_frames, num_frames);
	while(reserved != num_frames) {
		// When we're not getting any frames, we might need to...
		kick_all_tx(server, iface);
		reserved = frame_queue__cons_reserve(&iface->umem->available_frames, num_frames);
		// XXX FIXME
		if(!session || !session_state_is_running(atomic_load(&session->state))) {
			debug_printf("STOP");
			pthread_spin_unlock(&iface->umem->frames_lock);
			return;
		}
	}

	for(size_t i = 0; i < num_frames; i++) {
		addrs[i] = frame_queue__cons_fetch(&iface->umem->available_frames, i);
	}
	frame_queue__pop(&iface->umem->available_frames, num_frames);
	pthread_spin_unlock(&iface->umem->frames_lock);
}

static char *prepare_frame(struct xsk_socket_info *xsk, u64 addr, u32 prod_tx_idx, size_t framelen)
{
	xsk_ring_prod__tx_desc(&xsk->tx, prod_tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, prod_tx_idx)->len = framelen;
	char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
	return pkt;
}

#ifdef RANDOMIZE_FLOWID
static short flowIdCtr = 0;
#endif
#ifdef RANDOMIZE_UNDERLAY_SRC
static short src_port_ctr = 0;
#endif

static inline void tx_handle_send_queue_unit_for_iface(
	struct sender_state *tx_state, struct xsk_socket_info *xsk, int ifid,
	u64 frame_addrs[SEND_QUEUE_ENTRIES_PER_UNIT], struct send_queue_unit *unit,
	u32 thread_id, u16 dst_port, bool is_index_transfer) {
	u32 num_chunks_in_unit = 0;
	struct path_set *pathset = pathset_read(tx_state, thread_id);
	for(u32 i = 0; i < SEND_QUEUE_ENTRIES_PER_UNIT; i++) {
		if(unit->paths[i] == UINT8_MAX) {
			break;
		}
		// TODO path idx may be larger if paths changed in meantime
		struct hercules_path *path = &pathset->paths[unit->paths[i]];
		if(path->ifid == ifid) {
			num_chunks_in_unit++;
		}
	}

	u32 idx;
	if(xsk_ring_prod__reserve(&xsk->tx, num_chunks_in_unit, &idx) != num_chunks_in_unit) {
		// As there are fewer frames in the loop than slots in the TX ring, this should not happen
		exit_with_error(NULL, EINVAL);
	}

	int current_frame = 0;
	for(u32 i = 0; i < SEND_QUEUE_ENTRIES_PER_UNIT; i++) {
		if(unit->paths[i] == UINT8_MAX) {
			break;
		}
		// TODO check idx not too large (see above)
		const struct hercules_path *path = &pathset->paths[unit->paths[i]];
		if(path->ifid != ifid) {
			continue;
		}
		u32 chunk_idx = unit->chunk_idx[i];
		if (!is_index_transfer &&
			chunk_idx >= tx_state->total_chunks){
			// Since we use the same send queue for both index and data
			// transfer, we don't know which one the dequeued chunk idx refers
			// to. This is only a problem right after the swap from index to
			// data transfer (when there might still be items in the send queue
			// that refer to the index transfer even though we've moved on) and
			// there are more index than data packets.
			// We need to send something though, since we've allocated the frame
			// already, so we just pretend it's chunk 0.
			debug_printf("Chunk idx too large, index leftover?");
			chunk_idx = 0;
		}
		const size_t chunk_start = (size_t)chunk_idx * tx_state->chunklen;
		size_t len =
			umin64(tx_state->chunklen, tx_state->filesize - chunk_start);
		if (is_index_transfer) {
			len = umin64(tx_state->chunklen, tx_state->index_size - chunk_start);
		}

		void *pkt = prepare_frame(xsk, frame_addrs[current_frame], idx + current_frame, path->framelen);
		frame_addrs[current_frame] = -1;
		current_frame++;
		void *rbudp_pkt = mempcpy(pkt, path->header.header, path->headerlen);

#ifdef RANDOMIZE_FLOWID
		short *flowId = (short *)&(
			(char *)pkt)[44];  // ethernet hdr (14), ip hdr (20), udp hdr (8),
							   // offset of flowId in scion hdr
		// XXX ^ ignores first 4 bits of flowId
		*flowId = atomic_fetch_add(&flowIdCtr, 1);
#endif
#ifdef RANDOMIZE_UNDERLAY_SRC
		short *src_port =
			(short *)&((char *)pkt)[34];  // Ethernet (14) + IP (20), src port
										  // is first 2 bytes of udp header
		*src_port = atomic_fetch_add(&src_port_ctr, 1);
#endif
		u8 track_path = PCC_NO_PATH;  // put path_idx iff PCC is enabled
		sequence_number seqnr = 0;
		if (path->cc_state != NULL) {
			track_path = unit->paths[i];
			seqnr = atomic_fetch_add(&path->cc_state->last_seqnr, 1);
		}
		u8 flags = 0;
		char *payload = tx_state->mem;
		if (is_index_transfer) {
			flags |= PKT_FLAG_IS_INDEX;
			payload = tx_state->index;
		}
		stitch_dst_port(path, dst_port, pkt);
		stitch_src_port(path, tx_state->src_port, pkt);
		fill_rbudp_pkt(rbudp_pkt, chunk_idx, track_path, flags, seqnr,
					   payload + chunk_start, len, path->payloadlen);
		stitch_checksum_with_dst(path, path->header.checksum, pkt);
	}
	xsk_ring_prod__submit(&xsk->tx, num_chunks_in_unit);
}

static inline void tx_handle_send_queue_unit(
	struct hercules_server *server, struct sender_state *tx_state,
	struct xsk_socket_info *xsks[],
	u64 frame_addrs[][SEND_QUEUE_ENTRIES_PER_UNIT],
	struct send_queue_unit *unit, u32 thread_id, u16 dst_port, bool is_index_transfer) {
	for(int i = 0; i < server->num_ifaces; i++) {
		tx_handle_send_queue_unit_for_iface(tx_state, xsks[i], server->ifaces[i].ifid, frame_addrs[i], unit, thread_id, dst_port, is_index_transfer);
	}
}

static void
produce_batch(struct hercules_server *server, struct hercules_session *session, const u8 *path_by_rcvr, const u32 *chunks,
			  const u8 *rcvr_by_chunk, u32 num_chunks)
{
	u32 chk;
	u32 num_chunks_in_unit;
	struct send_queue_unit *unit = NULL;
	for(chk = 0; chk < num_chunks; chk++) {
		if(unit == NULL) {
			unit = send_queue_reserve(session->send_queue);
			num_chunks_in_unit = 0;
			if(unit == NULL) {
				// send_queue is full, make sure that the frame_queue does not drain in the meantime
				for(int i = 0; i < server->num_ifaces; i++) {
					pop_completion_ring(server, server->ifaces[i].umem);
				}
				chk--; // retry with same chunk
				continue;
			}
		}

		/* unit->rcvr[num_chunks_in_unit] = rcvr_by_chunk[chk]; */
		unit->paths[num_chunks_in_unit] = path_by_rcvr[rcvr_by_chunk[chk]];
		unit->chunk_idx[num_chunks_in_unit] = chunks[chk];

		num_chunks_in_unit++;
		if(num_chunks_in_unit == SEND_QUEUE_ENTRIES_PER_UNIT || chk == num_chunks - 1) {
			if(num_chunks_in_unit < SEND_QUEUE_ENTRIES_PER_UNIT) {
				unit->paths[num_chunks_in_unit] = UINT8_MAX;
			}
			send_queue_push(session->send_queue);
			unit = NULL;
		}
	}
}

static inline void allocate_tx_frames(struct hercules_server *server,
									  struct hercules_session *session,
									  u64 frame_addrs[][SEND_QUEUE_ENTRIES_PER_UNIT])
{
	for(int i = 0; i < server->num_ifaces; i++) {
		int num_frames;
		for(num_frames = 0; num_frames < SEND_QUEUE_ENTRIES_PER_UNIT; num_frames++) {
			if(frame_addrs[i][num_frames] != (u64) -1) {
				break;
			}
		}
		claim_tx_frames(server, session, &server->ifaces[i], frame_addrs[i], num_frames);
	}
}

// Compute rate limit for the path currently marked active
static u32 compute_max_chunks_current_path(struct sender_state *tx_state, struct path_set *pathset) {
	u32 allowed_chunks = 0;
	u64 now = get_nsecs();

	// TODO make sure path_index is reset correctly on pathset change
	struct hercules_path *path = &pathset->paths[pathset->path_index];
	if (!path->enabled) {
		return 0;  // if a receiver does not have any enabled paths, we can
				   // actually end up here ... :(
	}

	if (path->cc_state) {	// use PCC
		struct ccontrol_state *cc_state = path->cc_state;
		allowed_chunks =
			umin32(BATCH_SIZE, ccontrol_can_send_npkts(cc_state, now));
	} else {  // no path-based limit
		allowed_chunks = BATCH_SIZE;
	}
	return allowed_chunks;
}


// Send a total max of BATCH_SIZE
static u32 shrink_sending_rates(struct sender_state *tx_state,
								u32 *max_chunks_per_rcvr, u32 total_chunks) {
	if (total_chunks > BATCH_SIZE) {
		u32 new_total_chunks =
			0;	// due to rounding errors, we need to aggregate again
		max_chunks_per_rcvr[0] =
			max_chunks_per_rcvr[0] * BATCH_SIZE / total_chunks;
		new_total_chunks += max_chunks_per_rcvr[0];
		return new_total_chunks;
	}
	return total_chunks;
}

// TODO remove
static inline void prepare_rcvr_paths(struct sender_state *tx_state, u8 *rcvr_path) {
	rcvr_path[0] = tx_state->pathset->path_index;
}

// Mark the next available path as active
static void iterate_paths(struct sender_state *tx_state, struct path_set *pathset) {
	if (pathset->n_paths == 0) {
		return;
	}
	u32 prev_path_index =
		pathset->path_index;  // we need this to break the loop if all paths
							  // are disabled
	if (prev_path_index >= pathset->n_paths) {
		prev_path_index = 0;
	}
	do {
		pathset->path_index = (pathset->path_index + 1) % pathset->n_paths;
	} while (!pathset->paths[pathset->path_index].enabled &&
			 pathset->path_index != prev_path_index);
}

static void terminate_cc(struct path_set *pathset) {
	for (u32 i = 0; i < pathset->n_paths; i++) {
		terminate_ccontrol(pathset->paths[i].cc_state);
	}
}

static void kick_cc(struct sender_state *tx_state, struct path_set *pathset) {
	if (tx_state->finished) {
		return;
	}
	for (u32 p = 0; p < pathset->n_paths; p++) {
		kick_ccontrol(pathset->paths[p].cc_state);
	}
}
// Select batch of un-ACKed chunks for (re)transmit:
// Batch ends if an un-ACKed chunk is encountered for which we should keep
// waiting a bit before retransmit.
//
// If a chunk can not yet be send, because we need to wait for an ACK, wait_until
// is set to the timestamp by which that ACK should arrive. Otherwise, wait_until
// is not modified.
static u32 prepare_rcvr_chunks(struct sender_state *tx_state, u32 rcvr_idx, u32 *chunks, u8 *chunk_rcvr, const u64 now,
                               u64 *wait_until, u32 num_chunks, bool is_index_transfer)
{
	u32 num_chunks_prepared = 0;
	u32 chunk_idx = tx_state->prev_chunk_idx;
	/* debug_printf("n chunks %d", num_chunks); */
	for(; num_chunks_prepared < num_chunks; num_chunks_prepared++) {
		/* debug_printf("prepared %d/%d chunks", num_chunks_prepared, num_chunks); */
		u32 total_chunks;
		if (is_index_transfer) {
			chunk_idx =
				bitset__scan_neg(&tx_state->acked_chunks_index, chunk_idx);
			total_chunks = tx_state->index_chunks;
		} else {
			chunk_idx = bitset__scan_neg(&tx_state->acked_chunks, chunk_idx);
			total_chunks = tx_state->total_chunks;
		}
		if (chunk_idx == total_chunks) {
			/* debug_printf("prev %d", rcvr->prev_chunk_idx); */
			if(tx_state->prev_chunk_idx == 0) { // this receiver has finished
				debug_printf("receiver has finished");
				tx_state->finished = true;
				break;
			}

			// switch round for this receiver:
			debug_printf("Receiver %d switches to next round", rcvr_idx);

			chunk_idx = 0;
			tx_state->prev_round_start = tx_state->prev_round_end;
			tx_state->prev_round_end = get_nsecs();
			u64 prev_round_dt = tx_state->prev_round_end - tx_state->prev_round_start;
			tx_state->prev_slope = (prev_round_dt + tx_state->total_chunks - 1) / tx_state->total_chunks; // round up
			tx_state->ack_wait_duration = 3 * (ACK_RATE_TIME_MS * 1000000UL + tx_state->handshake_rtt);
			break;
		}

		const u64 prev_transmit = umin64(tx_state->prev_round_start + tx_state->prev_slope * chunk_idx, tx_state->prev_round_end);
		const u64 ack_due = prev_transmit + tx_state->ack_wait_duration; // 0 for first round
		if(now >= ack_due) { // add the chunk to the current batch
			*chunks = chunk_idx++;
			*chunk_rcvr = rcvr_idx;
			chunks++;
			chunk_rcvr++;
		} else { // no chunk to send - skip this receiver in the current batch
			(*wait_until) = ack_due;
			break;
		}
	}
	tx_state->prev_chunk_idx = chunk_idx;
	return num_chunks_prepared;
}

// Initialise new sender state. Returns null in case of error.
static struct sender_state *init_tx_state(struct hercules_session *session,
										  size_t filesize, int chunklen,
										  size_t index_chunks, char *index,
										  int max_rate_limit, char *mem,
										  struct hercules_path *paths,
										  u32 num_dests, const int num_paths,
										  u32 max_paths_per_dest, u32 num_threads, u16 src_port) {
	u64 total_chunks = (filesize + chunklen - 1) / chunklen;
	if (total_chunks >= UINT_MAX) {
		fprintf(stderr,
				"File too big, not enough chunks available (chunks needed: "
				"%llu, chunks available: %u)\n",
				total_chunks, UINT_MAX - 1);
		// TODO update monitor err
		return NULL;
	}

	struct sender_state *tx_state = calloc(1, sizeof(*tx_state));
	if (tx_state == NULL){
		return NULL;
	}
	tx_state->session = session;
	tx_state->filesize = filesize;
	tx_state->chunklen = chunklen;
	tx_state->total_chunks = total_chunks;
	tx_state->index_chunks = index_chunks;
	tx_state->mem = mem;
	tx_state->index = index;
	tx_state->rate_limit = max_rate_limit;
	tx_state->start_time = 0;
	tx_state->end_time = 0;
	tx_state->src_port = src_port;

	bitset__create(&tx_state->acked_chunks, tx_state->total_chunks);
	bitset__create(&tx_state->acked_chunks_index, index_chunks);
	tx_state->handshake_rtt = 0;
	struct path_set *pathset = calloc(1, sizeof(*tx_state->pathset));
	if (pathset == NULL){
		free(tx_state);
		return NULL;
	}
	pathset->n_paths = num_paths;
	memcpy(pathset->paths, paths, sizeof(*paths)*num_paths);
	tx_state->pathset = pathset;

	// tx_p uses index 0, tx_send_p threads start at index 1
	int err = posix_memalign((void **)&tx_state->epochs, CACHELINE_SIZE,
							 sizeof(*tx_state->epochs)*(num_threads+1));
	if (err != 0) {
		free(pathset);
		free(tx_state);
		return NULL;
	}
	memset(tx_state->epochs, 0, sizeof(*tx_state->epochs) * (num_threads + 1));
	tx_state->next_epoch = 1;
	return tx_state;
}

static void reset_tx_state(struct sender_state *tx_state) {
	tx_state->finished = false;
	tx_state->prev_chunk_idx = 0;
}

// (Re)send HS if needed
static void tx_retransmit_initial(struct hercules_server *server, int s, u64 now) {
	struct hercules_session *session_tx = server->sessions_tx[s];
	if (session_tx && session_tx->state == SESSION_STATE_PENDING) {
		if (now > session_tx->last_pkt_sent + session_hs_retransmit_interval) {
			struct sender_state *tx_state = session_tx->tx_state;
			struct path_set *pathset = tx_state->pathset;
			// We always use the first path as the return path
			tx_send_initial(server, &pathset->paths[0], tx_state->index,
							tx_state->index_size, s, session_tx->dst_port,
							tx_state->filesize, tx_state->chunklen, now, 0,
							true, true);
			session_tx->last_pkt_sent = now;
		}
	}
}

static void tx_handle_hs_confirm(struct hercules_server *server,
								 struct rbudp_initial_pkt *parsed_pkt,
								 u16 dst_port, u16 src_port) {
	struct hercules_session *session_tx = lookup_session_tx(server, dst_port);
	if (session_tx != NULL &&
		session_tx->state == SESSION_STATE_PENDING) {
		struct sender_state *tx_state = session_tx->tx_state;
		// This is a reply to the very first packet and confirms connection
		// setup
		if (!(parsed_pkt->flags & HANDSHAKE_FLAG_NEW_TRANSFER)) {
			debug_printf("Handshake did not have correct flag set");
			return;
		}
		if (server->enable_pcc) {
			struct path_set *pathset = tx_state->pathset;
			u64 now = get_nsecs();
			tx_state->handshake_rtt = now - parsed_pkt->timestamp;
			// TODO where to get rate limit?
			// below is ~in Mb/s (but really pps)
			/* u32 rate = 20000e3; // 200 Gbps */
			u32 rate = 100; // 1 Mbps
			debug_printf("rate limit %u", rate);
			for (u32 i = 0; i < pathset->n_paths; i++){
				pathset->paths[i].cc_state = init_ccontrol_state(
					rate, tx_state->total_chunks,
					pathset->n_paths);
			}
			ccontrol_update_rtt(pathset->paths[0].cc_state,
								tx_state->handshake_rtt);
			// Return path is always idx 0
			fprintf(stderr,
					"[receiver %d] [path 0] handshake_rtt: "
					"%fs, MI: %fs\n",
					0, tx_state->handshake_rtt / 1e9,
					pathset->paths[0].cc_state->pcc_mi_duration);

			// TODO setting HS ok can be moved outside the if-pcc block
			// make sure we later perform RTT estimation
			// on every enabled path
			pathset->paths[0].next_handshake_at =
				UINT64_MAX;	 // We just completed the HS for this path
			for (u32 p = 1; p < pathset->n_paths; p++) {
				pathset->paths[p].next_handshake_at = now;
			}
		}
		tx_state->start_time = get_nsecs();
		session_tx->dst_port = src_port;
		if (parsed_pkt->flags & HANDSHAKE_FLAG_INDEX_FOLLOWS) {
			// Need to do index transfer first
			// XXX relying on data echoed back by receiver instead of local
			// state
			session_tx->state = SESSION_STATE_RUNNING_IDX;
		} else {
			// Index transfer not needed, straight to data transfer
			session_tx->state = SESSION_STATE_WAIT_CTS;
		}
		return;
	}

	if (session_tx != NULL && session_state_is_running(session_tx->state)) {
		struct sender_state *tx_state = session_tx->tx_state;
		struct path_set *pathset = tx_state->pathset;
		// This is a reply to some handshake we sent during an already
		// established session (e.g. to open a new path)
		u64 now = get_nsecs();
		if (server->enable_pcc) {
			ccontrol_update_rtt(pathset->paths[parsed_pkt->path_index].cc_state,
								now - parsed_pkt->timestamp);
		}
		pathset->paths[parsed_pkt->path_index].next_handshake_at = UINT64_MAX;

		// We have a new return path, redo handshakes on all other paths
		if (parsed_pkt->flags & HANDSHAKE_FLAG_SET_RETURN_PATH){
			tx_state->handshake_rtt = now - parsed_pkt->timestamp;
			for (u32 p = 0; p < pathset->n_paths; p++){
				if (p != parsed_pkt->path_index && pathset->paths[p].enabled){
					pathset->paths[p].next_handshake_at = now;
					pathset->paths[p].cc_state->pcc_mi_duration = DBL_MAX;
					pathset->paths[p].cc_state->rtt = DBL_MAX;
				}
			}
		}
		return;
	}
	// In other cases we just drop the packet
	debug_printf("Dropping HS confirm packet, was not expecting one");
}

static void replace_dir(char *entry, char *src, char *dst) {
	int oldlen = strlen(src);
	int entry_size = strlen(entry) - oldlen + 1;

}

// Map the provided file into memory for reading. Returns pointer to the mapped
// area, or null on error.
static char *tx_mmap(char *fname, char *dstname, size_t *filesize, void **index_o, u64 *index_size_o) {
	FTS *fts = NULL;
	FTSENT *ent = NULL;
	debug_printf("opening");
	char* fts_arg[2] = {fname, NULL};
	fts = fts_open(fts_arg, FTS_PHYSICAL, NULL);	// Don't follow symlinks
	if (fts == NULL) {
		return NULL;
	}
	debug_printf("fts open");
	int index_cap = 4096;
	void *index = malloc(index_cap);
	if (index == NULL){
		fts_close(fts);
		return NULL;
	}
	int index_size = 0;

	int total_filesize = 0;
	int real_filesize = 0;

	while ((ent = fts_read(fts)) != NULL) {
		switch (ent->fts_info) {
			case FTS_F:;  // Regular file
				int entry_size =
					sizeof(struct dir_index_entry) + ent->fts_pathlen + 1;
				debug_printf("entry size %d", entry_size);
				if (index_size + entry_size >= index_cap) {
					debug_printf("need realloc");
					index = realloc(index, index_cap + 4096);
					if (index == NULL) {
						fts_close(fts);
						return NULL;
					}
					index_cap += 4096;
				}
				debug_printf("adding to index: %s (%ldB)", ent->fts_path, ent->fts_statp->st_size);
				struct dir_index_entry *newentry =
					(struct dir_index_entry *)(index + index_size);

				newentry->filesize = ent->fts_statp->st_size;
				newentry->type = INDEX_TYPE_FILE;
				newentry->path_len = ent->fts_pathlen + 1;
				debug_printf("pathlen %d", ent->fts_pathlen);
				strncpy(newentry->path, ent->fts_path, newentry->path_len);
				debug_printf("Readback: %s (%d) %dB", newentry->path,
							 newentry->type, newentry->filesize);
				index_size += entry_size;
				u32 filesize_up =
					((4096 - 1) & newentry->filesize)
						? ((newentry->filesize + 4096) & ~(4096 - 1))
						: newentry->filesize;
				debug_printf("size was %x, up %x", newentry->filesize, filesize_up);
					total_filesize += filesize_up;
					real_filesize += newentry->filesize;
				break;
			case FTS_D:;	  // Directory
				entry_size =
					sizeof(struct dir_index_entry) + ent->fts_pathlen + 1;
				if (index_size + entry_size >= index_cap) {
					debug_printf("need realloc");
					index = realloc(index, index_cap + 4096);
					if (index == NULL) {
						fts_close(fts);
						return NULL;
					}
					index_cap += 4096;
				}
				debug_printf("adding to index: %s (%ldB)", ent->fts_path, ent->fts_statp->st_size);
				newentry =
					(struct dir_index_entry *)(index + index_size);
				newentry->filesize = 0;
				newentry->type = INDEX_TYPE_DIR;
				newentry->path_len = ent->fts_pathlen + 1;
				strncpy(newentry->path, ent->fts_path, newentry->path_len);
				index_size += entry_size;
				break;
			default:
				break;
		}
	}

	fts_close(fts);
	debug_printf("total filesize %d", total_filesize);
	debug_printf("real filesize %d", real_filesize);
	debug_printf("total entry size %d", index_size);
	char *mem = mmap(NULL, total_filesize, PROT_READ, MAP_PRIVATE | MAP_ANON, 0, 0);
	if (mem == MAP_FAILED) {
		return NULL;
	}
	char *next_mapping = mem;
	void *dst_index = malloc(index_cap);
	if (index == NULL){
		// TODO
		return NULL;
	}
	int dst_index_cap = 4096;
	int dst_index_size = 0;

	struct dir_index_entry *p = index;
	while (1) {
		debug_printf("Read: %s (%d) %dB", p->path, p->type, p->filesize);
		int src_path_len = strlen(p->path);
		int src_root_len = strlen(fname);
		int dst_root_len = strlen(dstname);
		int dst_path_len = src_path_len - src_root_len + dst_root_len;
		debug_printf("src path %d, root %d. dst path %d, root %d", src_path_len, src_root_len, dst_path_len, dst_root_len);
		int entry_size = sizeof(struct dir_index_entry) + dst_path_len + 1;
		if (dst_index_size + entry_size >= dst_index_cap) {
			debug_printf("need realloc");
			dst_index = realloc(dst_index, dst_index_cap + 4096);
			if (dst_index == NULL) {
				fts_close(fts);
				return NULL;
			}
			dst_index_cap += 4096;
		}
		struct dir_index_entry *newentry = (struct dir_index_entry *)(dst_index + dst_index_size);
		debug_printf("entry size %d, index size %d", entry_size, dst_index_size);
		newentry->filesize = p->filesize;
		newentry->type = p->type;
		newentry->path_len = dst_path_len + 1;
		strncpy(newentry->path, dstname, dst_root_len);
		strncpy(&newentry->path[dst_root_len], &p->path[src_root_len],
				dst_path_len - dst_root_len + 1);
		debug_printf("Set dst path %s", newentry->path);
		dst_index_size += entry_size;

		if (p->type == INDEX_TYPE_FILE) {
			int f = open(p->path, O_RDONLY);
			if (f == -1) {
				return NULL;
			}
			char *filemap = mmap(next_mapping, p->filesize, PROT_READ,
								 MAP_PRIVATE | MAP_FIXED, f, 0);
			if (filemap == MAP_FAILED) {
				debug_printf("filemap err! %d", errno);
				return NULL;
			}
				u32 filesize_up =
					((4096 - 1) & p->filesize)
						? ((p->filesize + 4096) & ~(4096 - 1))
						: p->filesize;
			next_mapping += filesize_up;
			close(f);
		}
		p = ((char *)p) + sizeof(*p) + p->path_len;
		if (p >= index + index_size) {
			break;
		}
	}
	free(index);

	*filesize = total_filesize;
	*index_o = dst_index;
	*index_size_o = dst_index_size;
	return mem;
}

/// PCC
#define NACK_TRACE_SIZE (1024*1024)
static u32 nack_trace_count = 0;
static struct {
	long long sender_timestamp;
	long long receiver_timestamp;
	u32 nr;
} nack_trace[NACK_TRACE_SIZE];

static void nack_trace_push(u64 timestamp, u32 nr) {
	return;
	u32 idx = atomic_fetch_add(&nack_trace_count, 1);
	if(idx >= NACK_TRACE_SIZE) {
		fprintf(stderr, "oops: nack trace too small, trying to push #%d\n", idx);
		exit(133);
	}
	nack_trace[idx].sender_timestamp = timestamp;
	nack_trace[idx].receiver_timestamp = get_nsecs();
	nack_trace[idx].nr = nr;
}

#define PCC_TRACE_SIZE (1024*1024)
static u32 pcc_trace_count = 0;
static struct {
	u64 time;
	sequence_number range_start, range_end, mi_min, mi_max;
	u32 excess;
	float loss;
	u32 delta_left, delta_right, nnacks, nack_pkts;
	enum pcc_state state;
	u32 target_rate, actual_rate;
	double target_duration, actual_duration;
} pcc_trace[PCC_TRACE_SIZE];

static void pcc_trace_push(u64 time, sequence_number range_start, sequence_number range_end, sequence_number mi_min,
						   sequence_number mi_max, u32 excess, float loss, u32 delta_left, u32 delta_right, u32 nnacks, u32 nack_pkts,
						   enum pcc_state state, u32 target_rate, u32 actual_rate, double target_duration, double actual_duration) {
	u32 idx = atomic_fetch_add(&pcc_trace_count, 1);
	if(idx >= PCC_TRACE_SIZE) {
		fprintf(stderr, "oops: pcc trace too small, trying to push #%d\n", idx);
		exit(133);
	}
	pcc_trace[idx].time = time;
	pcc_trace[idx].range_start = range_start;
	pcc_trace[idx].range_end = range_end;
	pcc_trace[idx].mi_min = mi_min;
	pcc_trace[idx].mi_max = mi_max;
	pcc_trace[idx].excess = excess;
	pcc_trace[idx].loss = loss;
	pcc_trace[idx].delta_left = delta_left;
	pcc_trace[idx].delta_right = delta_right;
	pcc_trace[idx].nnacks = nnacks;
	pcc_trace[idx].nack_pkts = nack_pkts;
	pcc_trace[idx].state = state;
	pcc_trace[idx].target_rate = target_rate;
	pcc_trace[idx].actual_rate = actual_rate;
	pcc_trace[idx].target_duration = target_duration;
	pcc_trace[idx].actual_duration = actual_duration;
}

static bool pcc_mi_elapsed(struct ccontrol_state *cc_state)
{
	if(cc_state->state == pcc_uninitialized) {
		return false;
	}
	unsigned long now = get_nsecs();
	sequence_number cur_seq = atomic_load(&cc_state->last_seqnr) - 1;
	sequence_number seq_rcvd = atomic_load(&cc_state->mi_seq_max);

	if (cc_state->mi_end <= now) {
		if (cc_state->mi_seq_end == 0) {
			cc_state->mi_end = now;
			cc_state->mi_seq_end = cur_seq;
		}
		if(cc_state->mi_seq_end != 0 &&
		   (cc_state->mi_seq_end < seq_rcvd || now > cc_state->mi_end + (unsigned long)(1.5e9 * cc_state->rtt))) {
			return true;
		}
	}
	return false;
}

static void pcc_monitor(struct sender_state *tx_state)
{
	struct path_set *pathset = tx_state->pathset;
	for(u32 cur_path = 0; cur_path < pathset->n_paths; cur_path++) {
		struct ccontrol_state *cc_state = pathset->paths[cur_path].cc_state;
		if (cc_state == NULL){ // Not using PCC
			continue;
		}
		pthread_spin_lock(&cc_state->lock);
		if(pcc_mi_elapsed(cc_state)) {
			u64 now = get_nsecs();
			if(cc_state->mi_end == 0) { // TODO should not be necessary
				fprintf(stderr, "Assumption violated.\n");
				quit_session(tx_state->session, SESSION_ERROR_PCC);
				cc_state->mi_end = now;
			}
			u32 throughput = cc_state->mi_seq_end - cc_state->mi_seq_start; // pkts sent in MI

			u32 excess = 0;
			if (cc_state->curr_rate * cc_state->pcc_mi_duration > throughput) {
				excess = cc_state->curr_rate * cc_state->pcc_mi_duration - throughput;
			}
			u32 lost_npkts = atomic_load(&cc_state->mi_nacked.num_set);
			// account for packets that are "stuck in queue"
			if(cc_state->mi_seq_end > cc_state->mi_seq_max) {
				lost_npkts += cc_state->mi_seq_end - cc_state->mi_seq_max;
			}
			lost_npkts = umin32(lost_npkts, throughput);
			float loss = (float)(lost_npkts + excess) / (throughput + excess);
			sequence_number start = cc_state->mi_seq_start;
			sequence_number end = cc_state->mi_seq_end;
			sequence_number mi_min = cc_state->mi_seq_min;
			sequence_number mi_max = cc_state->mi_seq_max;
			sequence_number delta_left = cc_state->mi_seq_start - cc_state->mi_seq_min;
			sequence_number delta_right = cc_state->mi_seq_max - cc_state->mi_seq_end;
			u32 nnacks = cc_state->num_nacks;
			u32 nack_pkts = cc_state->num_nack_pkts;
			enum pcc_state state = cc_state->state;
			double actual_duration = (double)(cc_state->mi_end - cc_state->mi_start) / 1e9;

			pcc_trace_push(now, start, end, mi_min, mi_max, excess, loss, delta_left, delta_right, nnacks, nack_pkts, state,
							cc_state->curr_rate * cc_state->pcc_mi_duration, throughput, cc_state->pcc_mi_duration, actual_duration);

			if(cc_state->num_nack_pkts != 0) { // skip PCC control if no NACKs received
				if(cc_state->ignored_first_mi) { // first MI after booting will only contain partial feedback, skip it as well
					pcc_control(cc_state, throughput, loss);
				}
				cc_state->ignored_first_mi = true;
			}

			// TODO move the neccessary ones to cc_start_mi below
			cc_state->mi_seq_min = UINT32_MAX;
			cc_state->mi_seq_max = 0;
			cc_state->mi_seq_max_rcvd = 0;
			atomic_store(&cc_state->num_nacks, 0);
			atomic_store(&cc_state->num_nack_pkts, 0);
			cc_state->mi_end = 0;

			// Start new MI; only safe because no acks are processed during those updates
			ccontrol_start_monitoring_interval(cc_state);
		}
		pthread_spin_unlock(&cc_state->lock);
	}
}

static inline bool pcc_has_active_mi(struct ccontrol_state *cc_state, u64 now)
{
	return cc_state->state != pcc_terminated &&
	       cc_state->state != pcc_uninitialized &&
	       cc_state->mi_start + (u64)((cc_state->pcc_mi_duration) * 1e9) >= now;
}

/// WORKER THREADS

// Read chunk ids from the send queue, fill in packets accorindgly and actually
// send them. This is the function run by the TX worker thread(s).
static void tx_send_p(void *arg) {
	struct worker_args *args = arg;
	struct hercules_server *server = args->server;
	int cur_session = 0;
	while (!wants_shutdown) {
		cur_session = ( cur_session + 1 ) % HERCULES_CONCURRENT_SESSIONS;
		struct hercules_session *session_tx = server->sessions_tx[cur_session];
		if (session_tx == NULL ||
			!session_state_is_running(session_tx->state)) {
			kick_tx_server(server);	 // flush any pending packets
			continue;
		}
		bool is_index_transfer = (session_tx->state == SESSION_STATE_RUNNING_IDX);
		struct send_queue_unit unit;
		int ret = send_queue_pop(session_tx->send_queue, &unit);
		if (!ret) {
			kick_tx_server(server);
			continue;
		}
		// The unit may contain fewer than the max number of chunks. We only
		// want to allocate as many frames as there are packets to send,
		// otherwise the unused frames would not be submitted to the TX rings
		// and thus be lost.
		u32 num_chunks_in_unit = 0;
		for (u32 i = 0; i < SEND_QUEUE_ENTRIES_PER_UNIT; i++) {
			if (unit.paths[i] == UINT8_MAX) {
				break;
			}
			num_chunks_in_unit++;
		}
		u64 frame_addrs[server->num_ifaces][SEND_QUEUE_ENTRIES_PER_UNIT];
		memset(frame_addrs, 0xFF, sizeof(frame_addrs));
		for (u32 i = 0; i < SEND_QUEUE_ENTRIES_PER_UNIT; i++) {
			if (i >= num_chunks_in_unit) {
				frame_addrs[0][i] = 0;
			}
		}
		allocate_tx_frames(server, session_tx, frame_addrs);
		tx_handle_send_queue_unit(server, session_tx->tx_state, args->xsks,
								  frame_addrs, &unit, args->id, session_tx->dst_port, is_index_transfer);
		atomic_fetch_add(&session_tx->tx_npkts, num_chunks_in_unit); // FIXME should this be here?
	}
}

// Send ACKs to the sender. Runs in its own thread.
static void rx_trickle_acks(void *arg) {
	struct hercules_server *server = arg;
	int cur_session = 0;
	while (!wants_shutdown) {
		cur_session = ( cur_session + 1 ) % HERCULES_CONCURRENT_SESSIONS;
		struct hercules_session *session_rx = server->sessions_rx[cur_session];
		if (session_rx != NULL && session_state_is_running(session_rx->state)) {
			struct receiver_state *rx_state = session_rx->rx_state;
			bool is_index_transfer = (session_rx->state == SESSION_STATE_RUNNING_IDX);
			// XXX: data races in access to shared rx_state!
			atomic_store(&rx_state->last_pkt_rcvd, get_nsecs()); // FIXME what?
			if (atomic_load(&rx_state->last_pkt_rcvd) +
					umax64(100 * ACK_RATE_TIME_MS * 1e6,
						   3 * rx_state->handshake_rtt) <
				get_nsecs()) {
				// Transmission timed out
				quit_session(session_rx, SESSION_ERROR_TIMEOUT);
			}
			rx_send_acks(server, rx_state, is_index_transfer);
			if (rx_received_all(rx_state, is_index_transfer)) {
				if (is_index_transfer) {
					debug_printf("Received entire index");
					rx_send_acks(server, rx_state, is_index_transfer);
					session_rx->state = SESSION_STATE_INDEX_READY;
				} else {
					debug_printf("Received all, done.");
					rx_send_acks(server, rx_state, is_index_transfer);
					quit_session(session_rx, SESSION_ERROR_OK);
				}
			}
		}
		sleep_nsecs(ACK_RATE_TIME_MS * 1e6);
	}
}

// Send NACKs to the sender. Runs in its own thread.
static void rx_trickle_nacks(void *arg) {
	struct hercules_server *server = arg;
	int cur_session = 0;
	while (!wants_shutdown) {
		cur_session = (cur_session + 1) % HERCULES_CONCURRENT_SESSIONS;
		struct hercules_session *session_rx = server->sessions_rx[cur_session];
		if (session_rx != NULL && session_state_is_running(session_rx->state)) {
			bool is_index_transfer =
				(session_rx->state == SESSION_STATE_RUNNING_IDX);
			struct receiver_state *rx_state = session_rx->rx_state;
			u32 ack_nr = rx_state->ack_nr;
			u64 now = get_nsecs();
			if (now < rx_state->next_nack_round_start) {
				continue;
			}
			u64 ack_round_start = now;
			rx_send_nacks(server, rx_state, ack_round_start, ack_nr,
						  is_index_transfer);
			u64 ack_round_end = get_nsecs();
			if (ack_round_end >
				ack_round_start + rx_state->handshake_rtt * 1000 / 4) {
				/* fprintf(stderr, "NACK send too slow (took %lld of %ld)\n", */
				/* 		ack_round_end - ack_round_start, */
				/* 		rx_state->handshake_rtt * 1000 / 4); */
			} else {
				rx_state->next_nack_round_start =
					ack_round_start + rx_state->handshake_rtt * 1000 / 4;
			}
			rx_state->ack_nr++;
		}
	}
}

// Receive data packets on the XDP sockets. Runs in the RX worker thread(s).
static void rx_p(void *arg) {
	struct worker_args *args = arg;
	struct hercules_server *server = args->server;
	int num_ifaces = server->num_ifaces;
	u32 i = 0;
	while (!wants_shutdown) {
		rx_receive_batch(server, args->xsks[i % num_ifaces]);
		i++;
	}
}

/**
 * Transmit and retransmit chunks that have not been ACKed.
 * For each retransmit chunk, wait (at least) one round trip time for the ACK to arrive.
 * For large files transfers, this naturally allows to start retransmitting chunks at the beginning
 * of the file, while chunks of the previous round at the end of the file are still in flight.
 *
 * Transmission through different paths is batched (i.e. use the same path within a batch) to prevent the receiver from
 * ACKing individual chunks.
 *
 * The estimates for the ACK-arrival time dont need to be accurate for correctness, i.e. regardless
 * of how bad our estimate is, all chunks will be (re-)transmitted eventually.
 *	 - if we *under-estimate* the RTT, we may retransmit chunks unnecessarily
 *	   - waste bandwidth, waste sender disk reads & CPU time, waste receiver CPU time
 *	   - potentially increase overall transmit time because necessary retransmit may be delayed by
 *	     wasted resources
 *	 - if we *over-estimate* the RTT, we wait unnecessarily
 *		 This is only constant overhead per retransmit round, independent of number of packets or send
 *		 rate.
 * Thus it seems preferrable to *over-estimate* the ACK-arrival time.
 *
 * To avoid recording transmit time per chunk, only record start and end time of a transmit round
 * and linearly interpolate for each receiver separately.
 * This assumes a uniform send rate and that chunks that need to be retransmitted (i.e. losses)
 * occur uniformly.
 */
static void *tx_p(void *arg) {
  struct hercules_server *server = arg;
  int cur_session = 0;
  while (!wants_shutdown) {
    /* pthread_spin_lock(&server->biglock); */
	cur_session = (cur_session +1) % HERCULES_CONCURRENT_SESSIONS;
    pop_completion_rings(server);
    u32 chunks[BATCH_SIZE];
    u8 chunk_rcvr[BATCH_SIZE];
    struct hercules_session *session_tx = server->sessions_tx[cur_session];
	if (session_tx != NULL &&
		session_state_is_running(atomic_load(&session_tx->state))) {
      struct sender_state *tx_state = session_tx->tx_state;
	  bool is_index_transfer = (session_tx->state == SESSION_STATE_RUNNING_IDX);
	  struct path_set *pathset = pathset_read(tx_state, 0);
      /* debug_printf("Start transmit round"); */
      tx_state->prev_rate_check = get_nsecs();

      pop_completion_rings(server);
      send_path_handshakes(server, tx_state, cur_session, pathset);
      u64 next_ack_due = 0;

		// in each iteration, we send packets on a single path to each receiver
		// collect the rate limits for each active path
		u32 allowed_chunks = compute_max_chunks_current_path(tx_state, pathset);

		if (allowed_chunks ==
			0) {  // we hit the rate limits on every path; switch paths
			iterate_paths(tx_state, pathset);
			continue;
		}

		// TODO re-enable?
		// sending rates might add up to more than BATCH_SIZE, shrink
		// proportionally, if needed
		/* shrink_sending_rates(tx_state, max_chunks_per_rcvr, total_chunks); */

		const u64 now = get_nsecs();
		u32 num_chunks = 0;
		if (!tx_state->finished) {
			u64 ack_due = 0;
			// for each receiver, we prepare up to max_chunks_per_rcvr[r] chunks
			// to send
			u32 cur_num_chunks = prepare_rcvr_chunks(
				tx_state, 0, &chunks[num_chunks], &chunk_rcvr[num_chunks], now,
				&ack_due, allowed_chunks, is_index_transfer);
			num_chunks += cur_num_chunks;
			if (tx_state->finished && !is_index_transfer) {
				terminate_cc(pathset);
				kick_cc(tx_state, pathset);
			} else {
				// only wait for the nearest ack
				if (next_ack_due) {
					if (next_ack_due > ack_due) {
						next_ack_due = ack_due;
					}
				} else {
					next_ack_due = ack_due;
				}
			}
		}

		if (num_chunks > 0) {
			u8 rcvr_path[1];
			prepare_rcvr_paths(tx_state, rcvr_path);
			produce_batch(server, session_tx, rcvr_path, chunks, chunk_rcvr,
						  num_chunks);
			tx_state->tx_npkts_queued += num_chunks;
			rate_limit_tx(tx_state);

			// update book-keeping
			u32 path_idx = pathset->path_index;
			struct ccontrol_state *cc_state = pathset->paths[path_idx].cc_state;
			if (cc_state != NULL) {
				// FIXME allowed_chunks below is not correct (3x)
				atomic_fetch_add(&cc_state->mi_tx_npkts, allowed_chunks);
				atomic_fetch_add(&cc_state->total_tx_npkts, allowed_chunks);
				if (pcc_has_active_mi(cc_state, now)) {
					atomic_fetch_add(&cc_state->mi_tx_npkts_monitored,
									 allowed_chunks);
				}
			}
		}

		iterate_paths(tx_state, pathset);

		if (now < next_ack_due) {
			// XXX if the session vanishes in the meantime, we might wait
			// unnecessarily
			sleep_until(next_ack_due);
		}
	}
  }

  return NULL;
}

/// Event handler tasks

static int find_free_tx_slot(struct hercules_server *server){
	for (int i = 0; i < HERCULES_CONCURRENT_SESSIONS; i++){
		if (server->sessions_tx[i] == NULL){
			return i;
		}
	}
	return -1;
}

static int find_free_rx_slot(struct hercules_server *server){
	for (int i = 0; i < HERCULES_CONCURRENT_SESSIONS; i++){
		if (server->sessions_rx[i] == NULL){
			return i;
		}
	}
	return -1;
}

// Check if the monitor has new transfer jobs available and, if so, start one
static void new_tx_if_available(struct hercules_server *server) {
	int session_slot = find_free_tx_slot(server);
	if (session_slot == -1){
		// no free tx slot
		return;
	}
	// We're the only thread adding/removing sessions, so if we found a free
	// slot it will still be free when we assign to it later on
	char fname[1000];
	memset(fname, 0, 1000);
	char destname[1000];
	memset(destname, 0, 1000);
	int count;
	u16 jobid;
	u16 payloadlen;
	u16 dst_port;

	int ret = monitor_get_new_job(server->usock, fname, destname, &jobid, &dst_port, &payloadlen);
	if (!ret) {
		return;
	}
	debug_printf("new job: %s -> %s", fname, destname);
	debug_printf("using tx slot %d", session_slot);

	if (sizeof(struct rbudp_initial_pkt) + rbudp_headerlen > (size_t)payloadlen) {
		debug_printf("supplied payloadlen too small");
		monitor_update_job(server->usock, jobid, SESSION_STATE_DONE, SESSION_ERROR_BAD_MTU, 0, 0);
		return;
	}

	size_t filesize;
	void *index;
	u64 index_size;
	char *mem = tx_mmap(fname, destname, &filesize, &index, &index_size);
	if (mem == NULL){
		debug_printf("mmap failed");
		monitor_update_job(server->usock, jobid, SESSION_STATE_DONE, SESSION_ERROR_MAP_FAILED, 0, 0);
		return;
	}
	debug_printf("Index totals %llu bytes, data size %llu bytes", index_size, filesize);
	debug_printf("Transfer index in %f packets", index_size/(double)payloadlen);
	u64 chunklen = payloadlen - rbudp_headerlen;
	u64 chunks_for_index = (index_size + chunklen - 1) / chunklen;
	if (chunks_for_index >= UINT_MAX) {
		fprintf(stderr,
				"Index too big, not enough chunks available (chunks needed: "
				"%llu, chunks available: %u)\n",
				chunks_for_index, UINT_MAX - 1);
		monitor_update_job(server->usock, jobid, SESSION_STATE_DONE, SESSION_ERROR_TOO_LARGE, 0, 0);
		return;
	}
	struct hercules_session *session = make_session(server);
	if (session == NULL){
		monitor_update_job(server->usock, jobid, SESSION_STATE_DONE, SESSION_ERROR_INIT, 0, 0);
		munmap(mem, filesize); // FIXME when to unmap?
		return;
	}
	session->state = SESSION_STATE_PENDING;
	session->payloadlen = payloadlen;
	session->jobid = jobid;
	session->dst_port = dst_port;

	int n_paths;
	struct hercules_path *paths;
	ret = monitor_get_paths(server->usock, jobid, payloadlen, &n_paths, &paths);
	if (!ret || n_paths == 0){
		debug_printf("error getting paths");
		munmap(mem, filesize);
		/* destroy_session(session); */ // FIXME
		monitor_update_job(server->usock, jobid, SESSION_STATE_DONE, SESSION_ERROR_NO_PATHS, 0, 0);
		return;
	}
	debug_printf("received %d paths", n_paths);

	u16 src_port = server->config.port_min + session_slot + 1;
	struct sender_state *tx_state = init_tx_state(
		session, filesize, chunklen, chunks_for_index, index, server->rate_limit, mem, paths, 1, n_paths,
		server->max_paths, server->n_threads, src_port);
	free(paths);
	strncpy(tx_state->filename, fname, 99);
	tx_state->index = index;
	tx_state->index_size = index_size;
	session->tx_state = tx_state;
	atomic_store(&server->sessions_tx[session_slot], session);
}

// Remove and free finished sessions
static void cleanup_finished_sessions(struct hercules_server *server, int s, u64 now) {
	// Wait for twice the session timeout before removing the finished
	// session (and thus before accepting new sessions). This ensures the
	// other party has also quit or timed out its session and won't send
	// packets that would then be mixed into future sessions.
	// XXX This depends on both endpoints sharing the same timeout value,
	// which is not negotiated but defined at the top of this file.
	struct hercules_session *session_tx = atomic_load(&server->sessions_tx[s]);
	if (session_tx && session_tx->state == SESSION_STATE_DONE) {
		if (now > session_tx->last_pkt_rcvd + session_timeout * 2) {
			u64 sec_elapsed = (now - session_tx->last_pkt_rcvd) / (int)1e9;
			u64 bytes_acked = session_tx->tx_state->chunklen *
							  session_tx->tx_state->acked_chunks.num_set;
			monitor_update_job(server->usock, session_tx->jobid,
							   session_tx->state, session_tx->error,
							   sec_elapsed, bytes_acked);
			struct hercules_session *current = session_tx;
			atomic_store(&server->sessions_tx[s], NULL);
			fprintf(stderr, "Cleaning up TX session %d...\n", s);
			// At this point we don't know if some other thread still has a
			// pointer to the session that it might dereference, so we
			// cannot safely free it. So, we record the pointer and defer
			// freeing it until after the next session has completed. At
			// that point, no references to the deferred session should be
			// around, so we then free it.
			destroy_session_tx(server->deferreds_tx[s]);
			server->deferreds_tx[s] = current;
		}
	}
	struct hercules_session *session_rx = atomic_load(&server->sessions_rx[s]);
	if (session_rx && session_rx->state == SESSION_STATE_DONE) {
		if (now > session_rx->last_pkt_rcvd + session_timeout * 2) {
			struct hercules_session *current = session_rx;
			atomic_store(&server->sessions_rx[s], NULL);
			fprintf(stderr, "Cleaning up RX session %d...\n", s);
			// See the note above on deferred freeing
			destroy_session_rx(server->deferreds_rx[s]);
			server->deferreds_rx[s] = current;
		}
	}
}

// Time out if no packets received for a while
static void mark_timed_out_sessions(struct hercules_server *server, int s, u64 now) {
	struct hercules_session *session_tx = server->sessions_tx[s];
	if (session_tx && session_tx->state != SESSION_STATE_DONE) {
		if (now > session_tx->last_pkt_rcvd + session_timeout) {
			quit_session(session_tx, SESSION_ERROR_TIMEOUT);
			debug_printf("Session (TX %2d) timed out!", s);
		}
	}
	struct hercules_session *session_rx = server->sessions_rx[s];
	if (session_rx && session_rx->state != SESSION_STATE_DONE) {
		if (now > session_rx->last_pkt_rcvd + session_timeout) {
			quit_session(session_rx, SESSION_ERROR_TIMEOUT);
			debug_printf("Session (RX %2d) timed out!", s);
		} else if (now >
				   session_rx->last_new_pkt_rcvd + session_stale_timeout) {
			quit_session(session_rx, SESSION_ERROR_STALE);
			debug_printf("Session (RX %2d) stale!", s);
		}
	}
}

static void tx_update_paths(struct hercules_server *server, int s) {
	struct hercules_session *session_tx = server->sessions_tx[s];
	if (session_tx && session_state_is_running(session_tx->state)) {
		debug_printf("Updating paths for TX %d", s);
		struct sender_state *tx_state = session_tx->tx_state;
		struct path_set *old_pathset = tx_state->pathset;
		int n_paths;
		struct hercules_path *paths;
		bool ret = monitor_get_paths(server->usock, session_tx->jobid,
									 session_tx->payloadlen, &n_paths, &paths);
		if (!ret) {
			debug_printf("error getting paths");
			return;
		}
		debug_printf("received %d paths", n_paths);
		if (n_paths == 0) {
			free(paths);
			quit_session(session_tx, SESSION_ERROR_NO_PATHS);
			return;
		}
		struct path_set *new_pathset = calloc(1, sizeof(*new_pathset));
		if (new_pathset == NULL) {
			// FIXME leak?
			return;
		}
		u32 new_epoch = tx_state->next_epoch;
		new_pathset->epoch = new_epoch;
		tx_state->next_epoch++;
		new_pathset->n_paths = n_paths;
		memcpy(new_pathset->paths, paths, sizeof(*paths) * n_paths);
		u32 path_lim = (old_pathset->n_paths > (u32)n_paths)
						   ? (u32)n_paths
						   : old_pathset->n_paths;
		bool replaced_return_path = false;
		struct ccontrol_state **replaced_cc =
			calloc(old_pathset->n_paths, sizeof(*replaced_cc));
		if (replaced_cc == NULL) {
			// FIXME leak?
			return;
		}
		for (u32 i = 0; i < old_pathset->n_paths; i++) {
			replaced_cc[i] = old_pathset->paths[i].cc_state;
		}
		for (u32 i = 0; i < path_lim; i++) {
			// Set these two values before the comparison or it would fail
			// even if paths are the same.
			new_pathset->paths[i].next_handshake_at =
				old_pathset->paths[i].next_handshake_at;
			new_pathset->paths[i].cc_state = old_pathset->paths[i].cc_state;

			// XXX This works, but it means we restart CC even if the path
			// has not changed (but the header has, eg. because the old one
			// expired). We could avoid this by having the monitor tell us
			// whether the path changed, as it used to.
			if (memcmp(&old_pathset->paths[i], &new_pathset->paths[i],
					   sizeof(struct hercules_path)) == 0) {
				// Old and new path are the same, CC state carries over.
				// Since we copied the CC state before just leave as-is.
				debug_printf("Path %d not changed", i);
				replaced_cc[i] = NULL;
			} else {
				debug_printf("Path %d changed, resetting CC", i);
				if (i == 0) {
					// Return path is always idx 0
					replaced_return_path = true;
				}
				// TODO whether to use pcc should be decided on a per-path
				// basis by the monitor
				if (server->enable_pcc) {
					// TODO assert chunk length fits onto path
					// The new path is different, restart CC
					// TODO where to get rate
					u32 rate = 100;
					new_pathset->paths[i].cc_state = init_ccontrol_state(
						rate, tx_state->total_chunks, new_pathset->n_paths);
					// Re-send a handshake to update path rtt
					new_pathset->paths[i].next_handshake_at = 0;
				}
			}
			if (replaced_return_path) {
				// If we changed the return path we re-send the handshake on
				// all paths to update RTT.
				debug_printf(
					"Re-sending HS on path %d because return path changed", i);
				new_pathset->paths[i].next_handshake_at = 0;
			}
		}
		// Finally, swap in the new pathset
		tx_state->pathset = new_pathset;
		free(paths);  // These were *copied* into the new pathset
		for (int i = 0; i < server->n_threads + 1; i++) {
			do {
				// Wait until the thread has seen the new pathset
			} while (tx_state->epochs[i].epoch != new_epoch);
		}
		for (u32 i = 0; i < old_pathset->n_paths; i++) {
			// If CC was replaced, this contains the pointer to the old CC
			// state. Otherwise it contains NULL, and we don't need to free
			// anything.
			free(replaced_cc[i]);
		}
		free(replaced_cc);
		free(old_pathset);
		debug_printf("done with update");
	}
}

static inline void count_received_pkt(struct hercules_session *session,
									  u32 path_idx) {
	atomic_fetch_add(&session->rx_npkts, 1);
	if (path_idx < PCC_NO_PATH && session->rx_state != NULL) {
		atomic_fetch_add(&session->rx_state->path_state[path_idx].rx_npkts, 1);
	}
}

struct prints{
	u32 rx_received;
	u32 tx_sent;
	u64 ts;
};

static void print_session_stats(struct hercules_server *server, u64 now,
								struct prints *tx, struct prints *rx) {
	fprintf(stderr, "\n");
	double send_rate_total = 0;
	double recv_rate_total = 0;
	for (int s = 0; s < HERCULES_CONCURRENT_SESSIONS; s++) {
		struct hercules_session *session_tx = server->sessions_tx[s];
		if (session_tx && session_tx->state != SESSION_STATE_DONE) {
			struct prints *p = &tx[s];
			u32 sent_now = session_tx->tx_npkts;
			u32 acked_count = session_tx->tx_state->acked_chunks.num_set;
			u32 total = session_tx->tx_state->acked_chunks.num;
			u64 tdiff = now - p->ts;
			p->ts = now;
			double send_rate_pps =
				(sent_now - p->tx_sent) / ((double)tdiff / 1e9);
			p->tx_sent = sent_now;
			double send_rate =
				8 * send_rate_pps * session_tx->tx_state->chunklen / 1e6;
			double progress_percent = acked_count / (double)total * 100;
			send_rate_total += send_rate;
			fprintf(stderr,
					"(TX %2d) [%4.1f] Chunks: %9u/%9u, rx: %9ld, tx:%9ld, rate "
					"%8.2f "
					"Mbps\n",
					s, progress_percent, acked_count, total,
					session_tx->rx_npkts, session_tx->tx_npkts, send_rate);
		}

		struct hercules_session *session_rx = server->sessions_rx[s];
		if (session_rx && session_rx->state != SESSION_STATE_DONE) {
			struct prints *p = &rx[s];
			u32 rec_count = session_rx->rx_state->received_chunks.num_set;
			u32 total = session_rx->rx_state->received_chunks.num;
			u32 rcvd_now = session_rx->rx_npkts;
			u64 tdiff = now - p->ts;
			p->ts = now;
			double recv_rate_pps =
				(rcvd_now - p->rx_received) / ((double)tdiff / 1e9);
			p->rx_received = rcvd_now;
			double recv_rate =
				8 * recv_rate_pps * session_rx->rx_state->chunklen / 1e6;
			recv_rate_total += recv_rate;
			double progress_percent = rec_count / (double)total * 100;
			fprintf(stderr,
					"(RX %2d) [%4.1f%%] Chunks: %9u/%9u, rx: %9ld, tx:%9ld, "
					"rate %8.2f "
					"Mbps\n",
					s, progress_percent, rec_count, total, session_rx->rx_npkts,
					session_rx->tx_npkts, recv_rate);
		}
	}
	fprintf(stderr, "TX Total Rate: %.2f Mbps\n", send_rate_total);
	fprintf(stderr, "RX Total Rate: %.2f Mbps\n", recv_rate_total);
}

static void tx_update_monitor(struct hercules_server *server, int s, u64 now) {
	struct hercules_session *session_tx = server->sessions_tx[s];
	if (session_tx != NULL && session_state_is_running(session_tx->state)) {
		bool ret = monitor_update_job(
			server->usock, session_tx->jobid, session_tx->state, 0,
			(now - session_tx->tx_state->start_time) / (int)1e9,
			session_tx->tx_state->chunklen *
				session_tx->tx_state->acked_chunks.num_set);
		if (!ret) {
			quit_session(session_tx, SESSION_ERROR_CANCELLED);
		}
	}
}

static void rx_send_cts(struct hercules_server *server, int s, u64 now) {
	struct hercules_session *session_rx = server->sessions_rx[s];
	if (session_rx != NULL && session_rx->state == SESSION_STATE_INDEX_READY) {
		struct receiver_state *rx_state = session_rx->rx_state;
		rx_state->mem =
			rx_mmap(rx_state->index, rx_state->index_size, rx_state->filesize);
		if (rx_state->mem == NULL) {
			quit_session(session_rx, SESSION_ERROR_MAP_FAILED);
			return;
		}
		rx_send_cts_ack(server, rx_state);
		session_rx->state = SESSION_STATE_RUNNING_DATA;
	}
}

static void stop_finished_sessions(struct hercules_server *server, int slot, u64 now) {
	struct hercules_session *session_tx = server->sessions_tx[slot];
	if (session_tx != NULL && session_tx->state != SESSION_STATE_DONE &&
		session_tx->error != SESSION_ERROR_NONE) {
		debug_printf("Stopping TX %d", slot);
		session_tx->state = SESSION_STATE_DONE;
	}
	struct hercules_session *session_rx = server->sessions_rx[slot];
	if (session_rx != NULL && session_rx->state != SESSION_STATE_DONE &&
		session_rx->error != SESSION_ERROR_NONE) {
		debug_printf("Stopping RX %d", slot);
		session_rx->state = SESSION_STATE_DONE;
	}
}

#define PRINT_STATS

// Read control packets from the control socket and process them; also handles
// interaction with the monitor
static void events_p(void *arg) {
	debug_printf("event listener thread started");
	struct hercules_server *server = arg;

	struct sockaddr_ll addr;
	socklen_t addr_size = sizeof(addr);
	char buf[HERCULES_MAX_PKTSIZE];
	const struct scionaddrhdr_ipv4 *scionaddrhdr;
	const struct udphdr *udphdr;

	u64 lastpoll = 0;
	struct prints tx[HERCULES_CONCURRENT_SESSIONS];
	struct prints rx[HERCULES_CONCURRENT_SESSIONS];
	memset(tx, 0, sizeof(tx));
	memset(rx, 0, sizeof(rx));
	int current_slot = 0;
	while (!wants_shutdown) {	 // event handler thread loop
		u64 now = get_nsecs();
		current_slot = (current_slot + 1) % HERCULES_CONCURRENT_SESSIONS;
		/* if (now > lastpoll + 1e9){ */
		// XXX run the following every n seconds or every n socket reads?
		// FIXME don't loop over all sessions, one at a time
		new_tx_if_available(server);
		mark_timed_out_sessions(server, current_slot, now);
		stop_finished_sessions(server, current_slot, now);
		cleanup_finished_sessions(server, current_slot, now);
		tx_retransmit_initial(server, current_slot, now);
		rx_send_cts(server, current_slot, now);
#ifdef PRINT_STATS
		if (now > lastpoll + 1e9) {
			print_session_stats(server, now, tx, rx);
			lastpoll = now;
		}
#endif
		/* if (now > lastpoll + 10e9){ */
		/* 	tx_update_paths(server); */
		/* 	lastpoll = now; */
		/* } */
		/* if (now > lastpoll + 20e9){ */
		/* 	tx_update_monitor(server, current_slot, now); */
		/* 	tx_update_paths(server, current_slot); */
		/* 	lastpoll = now; */
		/* } */
		/* 	lastpoll = now; */
		/* } */

		// We want to handle received packets more frequently than we poll the
		// monitor or check for expired sessions, so try to receive 1000 times
		// (non-blocking) before doing anything else.
		for (int i = 0; i < 1000; i++) {
			ssize_t len = recvfrom(server->control_sockfd, buf, sizeof(buf),
								   MSG_DONTWAIT, (struct sockaddr *)&addr,
								   &addr_size);	 // XXX set timeout
			if (len == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
					continue;
				}
				exit_with_error(server,
								errno);	 // XXX: are there situations where we
										 // want to try again?
			}

			// Check the packet was received on an interface used by Hercules
			if (get_interface_by_id(server, addr.sll_ifindex) == NULL) {
				continue;
			}

			u8 scmp_bad_path = PCC_NO_PATH;
			u16 scmp_bad_port = 0;
			const char *rbudp_pkt =
				parse_pkt(server, buf, len, true, &scionaddrhdr, &udphdr,
						  &scmp_bad_path, &scmp_bad_port);
			if (rbudp_pkt == NULL) {
				if (scmp_bad_path != PCC_NO_PATH) {
					debug_printf("Received SCMP error on path %d, dst port %u, disabling",
								 scmp_bad_path, scmp_bad_port);
					// XXX We disable the path that received an SCMP error. The
					// next time we fetch new paths from the monitor it will be
					// re-enabled, if it's still present. It may be desirable to
					// retry a disabled path earlier, depending on how often we
					// update paths and on the exact SCMP error. Also, should
					// "destination unreachable" be treated as a permanent
					// failure and the session abandoned immediately?
					struct hercules_session *session_tx = lookup_session_tx(server, scmp_bad_port);
					if (session_tx != NULL &&
						session_state_is_running(session_tx->state)) {
						struct path_set *pathset =
							session_tx->tx_state->pathset;
						if (scmp_bad_path < pathset->n_paths) {
							pathset->paths[scmp_bad_path].enabled = false;
						}
					}
				}
				continue;
			}
			u16 pkt_dst_port = ntohs(*(u16 *)( rbudp_pkt - 6 ));
			u16 pkt_src_port = ntohs(*(u16 *)( rbudp_pkt - 8 ));

			const size_t rbudp_len = len - (rbudp_pkt - buf);
			if (rbudp_len < sizeof(u32)) {
				debug_printf("Ignoring, length too short");
				continue;
			}

			u32 chunk_idx;
			memcpy(&chunk_idx, rbudp_pkt, sizeof(u32));
			if (chunk_idx != UINT_MAX) {
				debug_printf("Ignoring, chunk_idx != UINT_MAX");
				continue;
			}

			debug_print_rbudp_pkt(rbudp_pkt, true);
			// TODO Count received pkt, call count_received_pkt everywhere

			// TODO check received packet has expected source address
			struct hercules_header *h = (struct hercules_header *)rbudp_pkt;
			if (h->chunk_idx == UINT_MAX) {	 // This is a control packet
				const char *pl = rbudp_pkt + rbudp_headerlen;
				struct hercules_control_packet *cp =
					(struct hercules_control_packet *)pl;
				u32 control_pkt_payloadlen = rbudp_len - rbudp_headerlen;

				switch (cp->type) {
					case CONTROL_PACKET_TYPE_INITIAL:;
						struct rbudp_initial_pkt *parsed_pkt = NULL;
						rbudp_check_initial(cp,
											rbudp_len - rbudp_headerlen,
											&parsed_pkt);
						if (parsed_pkt->flags & HANDSHAKE_FLAG_HS_CONFIRM) {
							// This is a confirmation for a handshake packet
							// we sent out earlier
							debug_printf("HS confirm packet");
							tx_handle_hs_confirm(server, parsed_pkt, pkt_dst_port, pkt_src_port);
							break;	// Make sure we don't process this further
						}
						// Otherwise, we process and reflect the packet
						struct hercules_session *session_rx = lookup_session_rx(server, pkt_dst_port);
						if (session_rx != NULL &&
							session_state_is_running(session_rx->state)) {
							if (!(parsed_pkt->flags &
								  HANDSHAKE_FLAG_NEW_TRANSFER)) {
								// This is a handshake that tries to open a new
								// path for the running transfer
								// Source port does not matter, so we pass 0
								rx_handle_initial(
									server, session_rx->rx_state,
									parsed_pkt, 0, buf, addr.sll_ifindex,
									rbudp_pkt + rbudp_headerlen, len);
							}
						}
						int rx_slot = find_free_rx_slot(server);
						if (rx_slot != -1 &&
							(parsed_pkt->flags & HANDSHAKE_FLAG_NEW_TRANSFER)) {
							// We don't have a running session and this is an
							// attempt to start a new one, go ahead and start a
							// new rx session
							debug_printf("Accepting new rx session");
							if (parsed_pkt->flags &
								HANDSHAKE_FLAG_SET_RETURN_PATH) {
								// The very first packet needs to set the return
								// path or we won't be able to reply
								struct hercules_session *session =
									make_session(server);
								server->sessions_rx[rx_slot] = session;
								session->state = SESSION_STATE_NEW;
								u16 src_port =
									server->config.port_min + rx_slot + 1;
								debug_printf("src port is %d", src_port);
								if (!(parsed_pkt->flags &
									  HANDSHAKE_FLAG_INDEX_FOLLOWS)) {
									// Entire index contained in this packet,
									// we can go ahead and proceed with transfer
									struct receiver_state *rx_state =
										make_rx_state(
											session, parsed_pkt->index,
											parsed_pkt->index_len,
											parsed_pkt->filesize,
											parsed_pkt->chunklen, src_port, false);
									if (rx_state == NULL) {
										debug_printf(
											"Error creating RX state!");
										break;
									}
									session->rx_state = rx_state;
									rx_handle_initial(
										server, rx_state, parsed_pkt, rx_slot, buf,
										addr.sll_ifindex,
										rbudp_pkt + rbudp_headerlen, len);
									rx_send_cts_ack(server, rx_state);
									session->state =
										SESSION_STATE_RUNNING_DATA;
								}
								else {
									// Index transferred separately
									struct receiver_state *rx_state =
										make_rx_state_nomap(
											session, parsed_pkt->index_len,
											parsed_pkt->filesize,
											parsed_pkt->chunklen, src_port, false);
									if (rx_state == NULL) {
										debug_printf(
											"Error creating RX state!");
										break;
									}
									rx_state->index_size = parsed_pkt->index_len;
									rx_state->index = calloc(1, parsed_pkt->index_len);
									if (rx_state->index == NULL){
										debug_printf("Error allocating index");
										break;
									}
									session->rx_state = rx_state;
									rx_handle_initial(
										server, rx_state, parsed_pkt, rx_slot, buf,
										addr.sll_ifindex,
										rbudp_pkt + rbudp_headerlen, len);
									session->state =
										SESSION_STATE_RUNNING_IDX;

								}
							}
						}
						break;

					case CONTROL_PACKET_TYPE_ACK:
						if (control_pkt_payloadlen < ack__len(&cp->payload.ack)){
							debug_printf("ACK packet too short");
							break;
						}
						struct hercules_session *session_tx =
							lookup_session_tx(server, pkt_dst_port);
						if (session_tx != NULL &&
							session_tx->state ==
								SESSION_STATE_WAIT_CTS) {
							if (cp->payload.ack.num_acks == 0) {
								debug_printf("CTS received");
								atomic_store(&session_tx->state,
											 SESSION_STATE_RUNNING_DATA);
							}
						}
						if (session_tx != NULL &&
							session_tx->state == SESSION_STATE_RUNNING_DATA) {
							tx_register_acks(&cp->payload.ack,
											 session_tx->tx_state);
							count_received_pkt(session_tx, h->path);
							atomic_store(&session_tx->last_pkt_rcvd, get_nsecs());
							if (tx_acked_all(session_tx->tx_state)) {
								debug_printf("TX done, received all acks (%d)", pkt_dst_port-server->config.port_min);
								quit_session(session_tx,
											 SESSION_ERROR_OK);
							}
						}
						if (session_tx != NULL &&
							session_tx->state == SESSION_STATE_RUNNING_IDX) {
							tx_register_acks_index(&cp->payload.ack,
											 session_tx->tx_state);
							count_received_pkt(session_tx, h->path);
							atomic_store(&session_tx->last_pkt_rcvd, get_nsecs());
							if (tx_acked_all_index(session_tx->tx_state)) {
								debug_printf("Index transfer done, received all acks");
								reset_tx_state(session_tx->tx_state);
								session_tx->state = SESSION_STATE_WAIT_CTS;
							}
						}
						break;

					case CONTROL_PACKET_TYPE_NACK:
						if (control_pkt_payloadlen <
							ack__len(&cp->payload.ack)) {
							debug_printf("NACK packet too short");
							break;
						}
						session_tx = lookup_session_tx(server, pkt_dst_port);
						if (session_tx != NULL &&
							session_state_is_running(
								session_tx->state)) {
							count_received_pkt(session_tx, h->path);
							nack_trace_push(cp->payload.ack.timestamp,
											cp->payload.ack.ack_nr);
							struct path_set *pathset =
								session_tx->tx_state->pathset;
							if (h->path > pathset->n_paths) {
								// The pathset was updated in the meantime and
								// there are now fewer paths, so ignore this
								break;
							}
							tx_register_nacks(
								&cp->payload.ack,
								pathset->paths[h->path].cc_state);
						}
						break;
					default:
						debug_printf("Received control packet of unknown type");
						break;
				}
			} else {
				// This should never happen beacuse the xdp program redirects
				// all data packets
				debug_printf("Non-control packet received on control socket");
			}
			struct hercules_session *session_tx =
				lookup_session_tx(server, pkt_dst_port);
			if (session_tx) {
				pcc_monitor(session_tx->tx_state);
			}
		}
	}
}

static pthread_t start_thread(struct hercules_server *server, void *(start_routine), void *arg)
{
	pthread_t pt;
	int ret = pthread_create(&pt, NULL, start_routine, arg);
	if(ret)
		exit_with_error(server, ret);
	return pt;
}

static void join_thread(struct hercules_server *server, pthread_t pt)
{
	int ret = pthread_join(pt, NULL);
	if(ret) {
		exit_with_error(server, ret);
	}
}
/// (TODO)stats
struct path_stats *make_path_stats_buffer(int num_paths) {
    struct path_stats *path_stats = calloc(1, sizeof(*path_stats) + num_paths * sizeof(path_stats->paths[0]));
    path_stats->num_paths = num_paths;
    return path_stats;
}

/* static struct hercules_stats tx_stats(struct sender_state *tx_state, struct path_stats* path_stats) */
/* { */
/*     if(path_stats != NULL && tx_state->receiver[0].cc_states != NULL) { */
/*         if(path_stats->num_paths < tx_state->num_receivers * tx_state->max_paths_per_rcvr) { */
/*             fprintf(stderr,"stats buffer not large enough: %d given, %d required\n", path_stats->num_paths, */
/*                     tx_state->num_receivers * tx_state->max_paths_per_rcvr); */
/*             exit_with_error(tx_state->session, EINVAL); */
/*         } */
/*         for(u32 r = 0; r < tx_state->num_receivers; r++) { */
/*             const struct sender_state_per_receiver *receiver = &tx_state->receiver[r]; */
/*             for(u32 p = 0; p < receiver->num_paths; p++) { */
/*                 path_stats->paths[r * tx_state->max_paths_per_rcvr + p].pps_target = receiver->cc_states[p].curr_rate; */
/*                 path_stats->paths[r * tx_state->max_paths_per_rcvr + p].total_packets = receiver->cc_states[p].total_tx_npkts; */
/*             } */
/*             memset(&path_stats->paths[r * tx_state->max_paths_per_rcvr + receiver->num_paths], 0, */
/*                    sizeof(path_stats->paths[0]) * (tx_state->max_paths_per_rcvr - receiver->num_paths)); */
/*         } */
/*     } */
/* 	u32 completed_chunks = 0; */
/* 	u64 rate_limit = 0; */
/* 	for(u32 r = 0; r < tx_state->num_receivers; r++) { */
/* 		const struct sender_state_per_receiver *receiver = &tx_state->receiver[r]; */
/* 		completed_chunks += tx_state->receiver[r].acked_chunks.num_set; */
/* 		for(u8 p = 0; p < receiver->num_paths; p++) { */
/* 			if(receiver->cc_states == NULL) { // no path-specific rate-limit */
/* 				rate_limit += tx_state->rate_limit; */
/* 			} else { // PCC provided limit */
/* 				rate_limit += receiver->cc_states[p].curr_rate; */
/* 			} */
/* 		} */
/* 	} */
/* 	return (struct hercules_stats){ */
/* 			.start_time = tx_state->start_time, */
/* 			.end_time = tx_state->end_time, */
/* 			.now = get_nsecs(), */
/* 			.tx_npkts = tx_state->session->tx_npkts, */
/* 			.rx_npkts = tx_state->session->rx_npkts, */
/* 			.filesize = tx_state->filesize, */
/* 			.framelen = tx_state->session->config.ether_size, */
/* 			.chunklen = tx_state->chunklen, */
/* 			.total_chunks = tx_state->total_chunks * tx_state->num_receivers, */
/* 			.completed_chunks = completed_chunks, */
/* 			.rate_limit = umin64(tx_state->rate_limit, rate_limit), */
/* 	}; */
/* } */

/* static struct hercules_stats rx_stats(struct receiver_state *rx_state, struct path_stats* path_stats) */
/* { */
/*     if(path_stats != NULL) { */
/*         if(path_stats->num_paths < rx_state->num_tracked_paths) { */
/*             fprintf(stderr,"stats buffer not large enough: %d given, %d required\n", path_stats->num_paths, */
/*                     rx_state->num_tracked_paths); */
/*             exit_with_error(rx_state->session, EINVAL); */
/*         } */
/*         for(u32 p = 0; p < rx_state->num_tracked_paths; p++) { */
/*             path_stats->paths[p].total_packets = rx_state->path_state[p].rx_npkts; */
/*         } */
/*     } */
/* 	return (struct hercules_stats){ */
/* 			.start_time = rx_state->start_time, */
/* 			.end_time = rx_state->end_time, */
/* 			.now = get_nsecs(), */
/* 			.tx_npkts = rx_state->session->tx_npkts, */
/* 			.rx_npkts = rx_state->session->rx_npkts, */
/* 			.filesize = rx_state->filesize, */
/* 			.framelen = rx_state->session->config.ether_size, */
/* 			.chunklen = rx_state->chunklen, */
/* 			.total_chunks = rx_state->total_chunks, */
/* 			.completed_chunks = rx_state->received_chunks.num_set, */
/* 			.rate_limit = 0 */
/* 	}; */
/* } */
/// Hercules main
void hercules_main(struct hercules_server *server) {
  debug_printf("Hercules main");

  int ret = xdp_setup(server);
  if (ret != 0){
	  fprintf(stderr, "Error in XDP setup!\n");
	  exit(1);
  }

  // Start the NACK sender thread
  debug_printf("starting NACK trickle thread");
  pthread_t trickle_nacks = start_thread(NULL, rx_trickle_nacks, server);

  // Start the ACK sender thread
  debug_printf("starting ACK trickle thread");
  pthread_t trickle_acks = start_thread(NULL, rx_trickle_acks, server);


  // Start the RX worker threads
  pthread_t rx_workers[server->n_threads];
  for (int i = 0; i < server->n_threads; i++) {
    debug_printf("starting thread rx_p %d", i);
    rx_workers[i] = start_thread(NULL, rx_p, server->worker_args[i]);
  }

  // Start the TX worker threads
  pthread_t tx_workers[server->n_threads];
  for (int i = 0; i < server->n_threads; i++) {
    debug_printf("starting thread tx_send_p %d", i);
    tx_workers[i] = start_thread(NULL, tx_send_p, server->worker_args[i]);
  }

  // Start the TX scheduler thread
  debug_printf("starting thread tx_p");
  pthread_t tx_p_thread = start_thread(NULL, tx_p, server);

  events_p(server);

  join_thread(server, trickle_acks);
  join_thread(server, trickle_nacks);
  join_thread(server, tx_p_thread);
  for (int i = 0; i < server->n_threads; i++){
	  join_thread(server, rx_workers[i]);
	  join_thread(server, tx_workers[i]);
  }

  xdp_teardown(server);
  exit(0);
}

void usage(){
	fprintf(stderr, "usage: ?? TODO\n");
	exit(1);
}

// TODO Test multiple interfaces
#define HERCULES_MAX_INTERFACES 1
int main(int argc, char *argv[]) {
  // Options:
  // -i interface
  // -l listen address
  // -z XDP zerocopy mode
  // -q queue
  // -t TX worker threads
  // -r RX worker threads
  unsigned int if_idxs[HERCULES_MAX_INTERFACES];
  int n_interfaces = 0;
  struct hercules_app_addr listen_addr = {.ia = 0, .ip = 0, .port = 0};
  int xdp_mode = XDP_COPY;
  int queue = 0;
  int tx_threads = 1;
  int rx_threads = 1;
  int opt;
  while ((opt = getopt(argc, argv, "i:l:q:t:r:z")) != -1) {
    switch (opt) {
    case 'i':
      debug_printf("Using interface %s", optarg);
      if (n_interfaces >= HERCULES_MAX_INTERFACES) {
        fprintf(stderr, "Too many interfaces specified\n");
        exit(1);
      }
      if_idxs[n_interfaces] = if_nametoindex(optarg);
      if (if_idxs[n_interfaces] == 0) {
        fprintf(stderr, "No such interface: %s\n", optarg);
        exit(1);
      }
      n_interfaces++;
      break;
    case 'l':;
      // Expect something of the form: 17-ffaa:1:fe2,192.168.50.2:123
      u64 ia;
      u16 *ia_ptr = (u16 *)&ia;
      char ip_str[100];
      u32 ip;
      u16 port;
      int ret = sscanf(optarg, "%hu-%hx:%hx:%hx,%99[^:]:%hu", ia_ptr + 3,
                       ia_ptr + 2, ia_ptr + 1, ia_ptr + 0, ip_str, &port);
      if (ret != 6) {
        fprintf(stderr, "Error parsing listen address\n");
        exit(1);
      }
      listen_addr.ia = htobe64(ia);
      listen_addr.port = htons(port);
      ret = inet_pton(AF_INET, ip_str, &listen_addr.ip);
      if (ret != 1) {
        fprintf(stderr, "Error parsing listen address\n");
        exit(1);
      }
      break;
    case 'q':
      queue = strtol(optarg, NULL, 10);
      if (errno == EINVAL || errno == ERANGE) {
        fprintf(stderr, "Error parsing queue\n");
        exit(1);
      }
      break;
    case 't':
      tx_threads = strtol(optarg, NULL, 10);
      if (errno == EINVAL || errno == ERANGE) {
        fprintf(stderr, "Error parsing number of tx threads\n");
        exit(1);
      }
      break;
    case 'r':
      rx_threads = strtol(optarg, NULL, 10);
      if (errno == EINVAL || errno == ERANGE) {
        fprintf(stderr, "Error parsing number of rx threads\n");
        exit(1);
      }
      break;
    case 'z':
      xdp_mode = XDP_ZEROCOPY;
      break;
    default:
      usage();
    }
  }
  if (n_interfaces == 0 || listen_addr.ip == 0) {
    fprintf(stderr, "Missing required argument\n");
    exit(1);
  }
  if (rx_threads != tx_threads) {
    // XXX This is not required, but if they are different we need to take care
    // to allocate the right number of sockets, or have XDP sockets that are
    // each used only for one of TX/RX
    fprintf(stderr, "TX/RX threads must match\n");
    exit(1);
  }
  debug_printf("Starting Hercules using queue %d, %d rx threads, %d tx "
               "threads, xdp mode 0x%x",
               queue, rx_threads, tx_threads, xdp_mode);

  bool enable_pcc = true;
  struct hercules_server *server =
	  hercules_init_server(if_idxs, n_interfaces, listen_addr, queue, xdp_mode,
						   rx_threads, false, enable_pcc);

  // Register a handler for SIGINT/SIGTERM for clean shutdown
  struct sigaction act = {0};
  act.sa_handler = hercules_stop;
  act.sa_flags = SA_RESETHAND;
  int ret = sigaction(SIGINT, &act, NULL);
  if (ret == -1){
	  fprintf(stderr, "Error registering signal handler\n");
	  exit(1);
  }
  ret = sigaction(SIGTERM, &act, NULL);
  if (ret == -1){
	  fprintf(stderr, "Error registering signal handler\n");
	  exit(1);
  }

  hercules_main(server);
}

/// Local Variables:
/// outline-regexp: "/// "
/// eval:(outline-minor-mode 1)
/// End:
