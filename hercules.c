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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
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

// TODO move and see if we can't use this from only 1 thread so no locks
int usock;
pthread_spinlock_t usock_lock;

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx,
						   sequence_number seqnr, const char *data, size_t n,
						   size_t payloadlen);

// Update header checksum according to packet contents
static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt);

void debug_print_rbudp_pkt(const char *pkt, bool recv);

static bool rbudp_check_initial(struct hercules_control_packet *pkt, size_t len, struct rbudp_initial_pkt **parsed_pkt);

static struct hercules_session *make_session(struct hercules_server *server);

/// OK COMMON

// Check the SCION UDP address matches the session's peer
static inline bool src_matches_address(struct hercules_session *session,
								const struct scionaddrhdr_ipv4 *scionaddrhdr,
								const struct udphdr *udphdr) {
	struct hercules_app_addr *addr = &session->peer;
	return scionaddrhdr->src_ia == addr->ia &&
		   scionaddrhdr->src_ip == addr->ip && udphdr->uh_sport == addr->port;
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
static inline void quit_session(struct hercules_session *s,
								enum session_error err) {
	s->error = err;
	s->state = SESSION_STATE_DONE;
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

/* #define DEBUG_PRINT_PKTS */
#ifdef DEBUG_PRINT_PKTS
// recv indicates whether printed packets should be prefixed with TX or RX
void debug_print_rbudp_pkt(const char *pkt, bool recv) {
	struct hercules_header *h = (struct hercules_header *)pkt;
	const char *prefix = (recv) ? "RX->" : "<-TX";
	printf("%s Header: IDX %u, Path %u, Seqno %u\n", prefix, h->chunk_idx,
		   h->path, h->seqno);
	if (h->chunk_idx == UINT_MAX) {
		// Control packets
		const char *pl = pkt + 9;
		struct hercules_control_packet *cp =
			(struct hercules_control_packet *)pl;
		switch (cp->type) {
			case CONTROL_PACKET_TYPE_INITIAL:
				printf(
					"%s   HS: Filesize %llu, Chunklen %u, TS %llu, Path idx "
					"%u, Flags "
					"0x%x, MTU %d, Name length %u [%s]\n",
					prefix, cp->payload.initial.filesize,
					cp->payload.initial.chunklen, cp->payload.initial.timestamp,
					cp->payload.initial.path_index, cp->payload.initial.flags,
					cp->payload.initial.etherlen, cp->payload.initial.name_len,
					cp->payload.initial.name);
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

// Initialise a new session. Returns null in case of error.
static struct hercules_session *make_session(struct hercules_server *server) {
	struct hercules_session *s;
	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	s->state = SESSION_STATE_NONE;
	int err = posix_memalign((void **)&s->send_queue, CACHELINE_SIZE,
							 sizeof(*s->send_queue));
	if (err != 0) {
		free(s);
		return NULL;
	}
	init_send_queue(s->send_queue, BATCH_SIZE);
	s->last_pkt_sent = 0;
	s->last_pkt_rcvd =
		get_nsecs();  // Set this to "now" to allow timing out HS at sender
					  // (when no packet was received yet), once packets are
					  // received it will be updated accordingly
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

	bitset__destroy(&session->tx_state->acked_chunks);
	free(session->tx_state->paths);
	bitset__destroy(&session->tx_state->cc_states->mi_nacked);
	free(session->tx_state->cc_states);
	free(session->tx_state);

	destroy_send_queue(session->send_queue);
	free(session->send_queue);
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

	bitset__destroy(&session->rx_state->received_chunks);
	free(session->rx_state);

	destroy_send_queue(session->send_queue);
	free(session->send_queue);
	free(session);
}

// Initialise the Hercules server. If this runs into trouble we just exit as
// there's no point in continuing.
struct hercules_server *hercules_init_server(
	int *ifindices, int num_ifaces, const struct hercules_app_addr local_addr,
	int queue, int xdp_mode, int n_threads, bool configure_queues) {
	struct hercules_server *server;
	server = calloc(1, sizeof(*server) + num_ifaces * sizeof(*server->ifaces));
	if (server == NULL) {
		exit_with_error(NULL, ENOMEM);
	}
	server->ifindices = ifindices;
	server->num_ifaces = num_ifaces;
	server->config.queue = queue;
	server->n_threads = n_threads;
	server->session_rx = NULL;
	server->session_tx = NULL;
	server->worker_args = calloc(server->n_threads, sizeof(struct rx_p_args *));
	if (server->worker_args == NULL){
		exit_with_error(NULL, ENOMEM);
	}
	server->config.local_addr = local_addr;
	server->config.configure_queues = configure_queues;
	server->enable_pcc =
		true;	// TODO this should be per-path or at least per-transfer

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

	pthread_spin_init(&usock_lock, PTHREAD_PROCESS_PRIVATE);

	server->control_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (server->control_sockfd == -1) {
		exit_with_error(server, 0);
	}
	debug_printf("init complete");
	return server;
}

/// OK PACKET PARSING
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

// Parse ethernet/IP/UDP/SCION/UDP packet,
// check that it is addressed to us,
// check SCION-UDP checksum if set.
// sets scionaddrh_o to SCION address header, if provided
// return rbudp-packet (i.e. SCION/UDP packet payload)
static const char *parse_pkt(const struct hercules_server *server, const char *pkt, size_t length, bool check,
                             const struct scionaddrhdr_ipv4 **scionaddrh_o, const struct udphdr **udphdr_o)
{
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
		if(next_header == L4_SCMP) {
			debug_printf("SCION/SCMP L4: not implemented, ignoring...");
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
	if(l4udph->dest != server->config.local_addr.port) {
		debug_printf("not addressed to us (L4 UDP port): %u", ntohs(l4udph->dest));
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

static void stitch_checksum(const struct hercules_path *path, u16 precomputed_checksum, char *pkt)
{
	chk_input chk_input_s;
	chk_input *chksum_struc = init_chk_input(&chk_input_s, 2);
	assert(chksum_struc);
	char *payload = pkt + path->headerlen;
	precomputed_checksum = ~precomputed_checksum; // take one complement of precomputed checksum
	chk_add_chunk(chksum_struc, (u8 *)&precomputed_checksum, 2); // add precomputed header checksum
	chk_add_chunk(chksum_struc, (u8 *)payload, path->payloadlen); // add payload
	u16 pkt_checksum = checksum(chksum_struc);

	mempcpy(payload - 2, &pkt_checksum, sizeof(pkt_checksum));
}

// Fill packet with n bytes from data and pad with zeros to payloadlen.
static void fill_rbudp_pkt(void *rbudp_pkt, u32 chunk_idx, u8 path_idx,
						   sequence_number seqnr, const char *data, size_t n,
						   size_t payloadlen) {
	void *rbudp_path_idx = mempcpy(rbudp_pkt, &chunk_idx, sizeof(chunk_idx));
	void *rbudp_seqnr = mempcpy(rbudp_path_idx, &path_idx, sizeof(path_idx));
	void *rbudp_payload = mempcpy(rbudp_seqnr, &seqnr, sizeof(seqnr));
	void *start_pad = mempcpy(rbudp_payload, data, n);
	if (sizeof(chunk_idx) + sizeof(path_idx) + n < payloadlen) {
		memset(start_pad, 0,
			   payloadlen - sizeof(chunk_idx) - sizeof(path_idx) - n);
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

/// OK RECEIVER

static bool rx_received_all(const struct receiver_state *rx_state)
{
	return (rx_state->received_chunks.num_set == rx_state->total_chunks);
}

static bool handle_rbudp_data_pkt(struct receiver_state *rx_state, const char *pkt, size_t length)
{
	if(length < rbudp_headerlen + rx_state->chunklen) {
		debug_printf("packet too short: have %lu, expect %d", length, rbudp_headerlen + rx_state->chunklen );
		return false;
	}

	u32 chunk_idx;
	memcpy(&chunk_idx, pkt, sizeof(u32));
	if(chunk_idx >= rx_state->total_chunks) {
		if(chunk_idx == UINT_MAX) {
			// control packet is handled elsewhere
		} else {
			fprintf(stderr, "ERROR: chunk_idx larger than expected: %u >= %u\n",
			        chunk_idx, rx_state->total_chunks);
		}
		return false;
	}

	u8 path_idx;
	mempcpy(&path_idx, &pkt[4], sizeof(u8));
	if(path_idx < PCC_NO_PATH) {
		sequence_number seqnr;
		memcpy(&seqnr, &pkt[5], sizeof(sequence_number));
		if(rx_state->path_state[path_idx].seq_rcvd.bitmap == NULL) {
                  // TODO compute correct number here
			bitset__create(&rx_state->path_state[path_idx].seq_rcvd, 200 * rx_state->total_chunks);
			// TODO work out wrap-around
		}
		if(seqnr >= rx_state->path_state[path_idx].seq_rcvd.num) {
			// XXX: currently we cannot track these sequence numbers, as a consequence congestion control breaks at this
			// point, abort.
			if(rx_state->session->state != SESSION_STATE_RUNNING) {
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
		prev = bitset__set_mt_safe(&rx_state->received_chunks, chunk_idx);
	}
	if(!prev) {
		const char *payload = pkt + rbudp_headerlen;
		const size_t chunk_start = (size_t)chunk_idx * rx_state->chunklen;
		const size_t len = umin64(rx_state->chunklen, rx_state->filesize - chunk_start);
		memcpy(rx_state->mem + chunk_start, payload, len);
		// Update last new pkt timestamp
		atomic_store(&rx_state->session->last_new_pkt_rcvd, get_nsecs());
	}
	return true;
}

static u32 fill_ack_pkt(struct receiver_state *rx_state, u32 first, struct rbudp_ack_pkt *ack, size_t max_num_acks)
{
	size_t e = 0;
	u32 curr = first;
	for(; e < max_num_acks;) {
		u32 begin = bitset__scan(&rx_state->received_chunks, curr);
		if(begin == rx_state->received_chunks.num) {
			curr = begin;
			break;
		}
		u32 end = bitset__scan_neg(&rx_state->received_chunks, begin + 1);
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
submit_rx_frames(struct hercules_session *session, struct xsk_umem_info *umem, const u64 *addrs, size_t num_frames)
{
	u32 idx_fq = 0;
	pthread_spin_lock(&umem->lock);
	size_t reserved = xsk_ring_prod__reserve(&umem->fq, num_frames, &idx_fq);
	while(reserved != num_frames) {
		reserved = xsk_ring_prod__reserve(&umem->fq, num_frames, &idx_fq);
		if(session == NULL || session->state != SESSION_STATE_RUNNING) {
			pthread_spin_unlock(&umem->lock);
			return;
		}
	}

	for(size_t i = 0; i < num_frames; i++) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) = addrs[i];
	}
	xsk_ring_prod__submit(&umem->fq, num_frames);
	pthread_spin_unlock(&umem->lock);
}

// Read a batch of data packets from the XSK
static void rx_receive_batch(struct receiver_state *rx_state,
							 struct xsk_socket_info *xsk) {
	u32 idx_rx = 0;
	int ignored = 0;

	size_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if (!rcvd) {
		return;
	}

	// optimistically update receive timestamp
	u64 now = get_nsecs();
	u64 old_last_pkt_rcvd = atomic_load(&rx_state->last_pkt_rcvd);
	if (old_last_pkt_rcvd < now) {
		atomic_compare_exchange_strong(&rx_state->last_pkt_rcvd,
									   &old_last_pkt_rcvd, now);
	}
	// TODO timestamps in multiple places...
	atomic_store(&rx_state->session->last_pkt_rcvd, now);

	u64 frame_addrs[BATCH_SIZE];
	for (size_t i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
		frame_addrs[i] = addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
		const char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		const char *rbudp_pkt = parse_pkt_fast_path(pkt, len, true, UINT32_MAX);
		if (rbudp_pkt) {
			debug_print_rbudp_pkt(rbudp_pkt, true);
			if (!handle_rbudp_data_pkt(rx_state, rbudp_pkt,
									   len - (rbudp_pkt - pkt))) {
				debug_printf("Non-data packet on XDP socket? Ignoring.");
				ignored++;
			}
		} else {
			debug_printf("Unparseable packet on XDP socket, ignoring");
			ignored++;
		}
	}
	xsk_ring_cons__release(&xsk->rx, rcvd);
	atomic_fetch_add(&rx_state->session->rx_npkts, (rcvd - ignored));
	submit_rx_frames(rx_state->session, xsk->umem, frame_addrs, rcvd);
}

static void rx_receive_and_drop(struct xsk_socket_info *xsk){
	u32 idx_rx = 0;
	size_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	u64 frame_addrs[BATCH_SIZE];
	for (size_t i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
		frame_addrs[i] = addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
		const char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
	}
	xsk_ring_cons__release(&xsk->rx, rcvd);
	submit_rx_frames(NULL, xsk->umem, frame_addrs, rcvd);
}

// Prepare a file and memory mapping to receive a file
static char *rx_mmap(const char *pathname, size_t filesize) {
	debug_printf("mmap file: %s", pathname);
	int ret;
	/*ret = unlink(pathname);
	if(ret && errno != ENOENT) {
		exit_with_error(server, errno);
	}*/
	int f = open(pathname, O_RDWR | O_CREAT | O_EXCL, 0664);
	if (f == -1 && errno == EEXIST) {
		f = open(pathname, O_RDWR | O_EXCL);
	}
	if (f == -1) {
		return NULL;
	}
	ret = fallocate(f, 0, 0, filesize);	 // Will fail on old filesystems (ext3)
	if (ret) {
		close(f);
		return NULL;
	}
	// TODO why shared mapping?
	char *mem = mmap(NULL, filesize, PROT_WRITE, MAP_SHARED, f, 0);
	if (mem == MAP_FAILED) {
		close(f);
		return NULL;
	}
	// TODO Shouldn't we keep the file open until the transfer is finished to
	// prevent it being messed with?
	close(f);
	return mem;
}

// Create new receiver state. Returns null in case of error.
static struct receiver_state *make_rx_state(struct hercules_session *session,
											char *filename, size_t namelen,
											size_t filesize, int chunklen,
											int etherlen,
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
	filename[namelen+1] = 0; // HACK FIXME
	rx_state->mem = rx_mmap(filename, filesize);
	if (rx_state->mem == NULL) {
		free(rx_state);
		return NULL;
	}
	rx_state->etherlen = etherlen;
	return rx_state;
}

// Update the reply path using the header from a received packet.
// The packet is sent to the monior, which will return a new header with the
// path reversed.
static bool rx_update_reply_path(
	struct receiver_state *rx_state, int ifid, int rx_sample_len,
	const char rx_sample_buf[XSK_UMEM__DEFAULT_FRAME_SIZE]) {
	debug_printf("Updating reply path");
	if (!rx_state) {
		debug_printf("ERROR: invalid rx_state");
		return false;
	}
	assert(rx_sample_len > 0);
	assert(rx_sample_len <= XSK_UMEM__DEFAULT_FRAME_SIZE);

	pthread_spin_lock(&usock_lock);
	// TODO writing to reply path needs sync?
	int ret = monitor_get_reply_path(usock, rx_sample_buf, rx_sample_len,
									 rx_state->etherlen, &rx_state->reply_path);
	pthread_spin_unlock(&usock_lock);
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
							struct receiver_state *rx_state,
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
	/* strncpy(control_pkt.payload.initial.name, pld->name, pld->name_len); */
	control_pkt.payload.initial.flags |= HANDSHAKE_FLAG_HS_CONFIRM;

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *)&control_pkt,
	               sizeof(control_pkt.type) + sizeof(control_pkt.payload.initial), path.payloadlen);
	stitch_checksum(&path, path.header.checksum, buf);

	send_eth_frame(server, &path, buf);
	atomic_fetch_add(&rx_state->session->tx_npkts, 1);
}

// Handle a received HS packet by reflecting it back to its sender and update
// the session's reply path if the corresponding flag was set
static void rx_handle_initial(struct hercules_server *server,
							  struct receiver_state *rx_state,
							  struct rbudp_initial_pkt *initial,
							  const char *buf, int ifid, const char *payload,
							  int payloadlen) {
	debug_printf("handling initial");
	const int headerlen = (int)(payload - buf);
	if (initial->flags & HANDSHAKE_FLAG_SET_RETURN_PATH) {
		rx_update_reply_path(rx_state, ifid, headerlen + payloadlen, buf);
	}
	rx_send_rtt_ack(server, rx_state,
					initial);  // echo back initial pkt to ACK filesize
}

// Send an empty ACK, indicating to the sender that it may start sending data
// packets.
// XXX This is not strictly necessary, I think. Once the ACK sender thread sees
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

	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *)&control_pkt,
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
							 struct hercules_path *path) {
	char buf[HERCULES_MAX_PKTSIZE];
	void *rbudp_pkt = mempcpy(buf, path->header.header, path->headerlen);

	fill_rbudp_pkt(
		rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *)control_pkt,
		sizeof(control_pkt->type) + ack__len(&control_pkt->payload.ack),
		path->payloadlen);
	stitch_checksum(path, path->header.checksum, buf);

	send_eth_frame(server, path, buf);
	atomic_fetch_add(&session->tx_npkts, 1);
}

// Send as many ACK packets as necessary to convey all received packet ranges
static void rx_send_acks(struct hercules_server *server, struct receiver_state *rx_state)
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
	u32 curr = fill_ack_pkt(rx_state, 0, &control_pkt.payload.ack, max_entries);
	send_control_pkt(server, rx_state->session, &control_pkt, &path);
	for(; curr < rx_state->total_chunks;) {
		curr = fill_ack_pkt(rx_state, curr, &control_pkt.payload.ack, max_entries);
		if(control_pkt.payload.ack.num_acks == 0) break;
		send_control_pkt(server, rx_state->session, &control_pkt, &path);
	}
}


static void rx_send_path_nacks(struct hercules_server *server, struct receiver_state *rx_state, struct receiver_state_per_path *path_state, u8 path_idx, u64 time, u32 nr)
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
		fill_rbudp_pkt(rbudp_pkt, UINT_MAX, path_idx, 0, (char *)&control_pkt,
		               sizeof(control_pkt.type) + ack__len(&control_pkt.payload.ack), path.payloadlen);
		stitch_checksum(&path, path.header.checksum, buf);

		send_eth_frame(server, &path, buf);
		atomic_fetch_add(&rx_state->session->tx_npkts, 1);
	}
	libbpf_smp_wmb();
	// FIXME spurious segfault on unlock
	pthread_spin_unlock(&path_state->seq_rcvd.lock);
	path_state->nack_end = nack_end;
}

// sends the NACKs used for congestion control by the sender
static void rx_send_nacks(struct hercules_server *server, struct receiver_state *rx_state, u64 time, u32 nr)
{
	u8 num_paths = atomic_load(&rx_state->num_tracked_paths);
	for(u8 p = 0; p < num_paths; p++) {
		rx_send_path_nacks(server, rx_state, &rx_state->path_state[p], p, time, nr);
	}
}

/// OK SENDER
static bool tx_acked_all(const struct sender_state *tx_state) {
	if (tx_state->acked_chunks.num_set != tx_state->total_chunks) {
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
		atomic_fetch_add(&server->session_tx->tx_npkts, entries);
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
tx_send_initial(struct hercules_server *server, const struct hercules_path *path, char *filename, size_t filesize, u32 chunklen, unsigned long timestamp, u32 path_index, u32 etherlen, bool set_return_path, bool new_transfer)
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
			.payload.initial = {
					.filesize = filesize,
					.chunklen = chunklen,
					.timestamp = timestamp,
					.path_index = path_index,
					.flags = flags,
					.name_len = strlen(filename),
					.etherlen = etherlen,
			},
	};
	assert(strlen(filename) < 100); // TODO
	strncpy(pld.payload.initial.name, filename, 100);
	fill_rbudp_pkt(rbudp_pkt, UINT_MAX, PCC_NO_PATH, 0, (char *)&pld, sizeof(pld.type) + sizeof(pld.payload.initial) + pld.payload.initial.name_len,
	               path->payloadlen);
	stitch_checksum(path, path->header.checksum, buf);

	send_eth_frame(server, path, buf);
	atomic_fetch_add(&server->session_tx->tx_npkts, 1);
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

void send_path_handshakes(struct hercules_server *server, struct sender_state *tx_state) {
  u64 now = get_nsecs();

  for (u32 p = 0; p < tx_state->num_paths; p++) {
    struct hercules_path *path = &tx_state->paths[p];
    if (path->enabled) {
      u64 handshake_at = atomic_load(&path->next_handshake_at);
      if (handshake_at < now) {
        if (atomic_compare_exchange_strong(&path->next_handshake_at,
                                           &handshake_at,
                                           now + PATH_HANDSHAKE_TIMEOUT_NS)) {
          debug_printf("sending hs on path %d", p);
		  // FIXME file name below?
          tx_send_initial(server, path, "abcd", tx_state->filesize,
                          tx_state->chunklen, get_nsecs(), p, 0,
                          false, false);
        }
      }
    }
  }
}

// TODO
static void update_hercules_tx_paths(struct sender_state *tx_state)
{
	return; // FIXME HACK
	/* tx_state->has_new_paths = false; */
	/* u64 now = get_nsecs(); */
	/* for(u32 r = 0; r < tx_state->num_receivers; r++) { */
	/* 	struct sender_state_per_receiver *receiver = &tx_state->receiver[r]; */
	/* 	receiver->num_paths = tx_state->shd_num_paths[r]; */

	/* 	bool replaced_return_path = false; */
	/* 	for(u32 p = 0; p < receiver->num_paths; p++) { */
	/* 		struct hercules_path *shd_path = &tx_state->shd_paths[r * tx_state->max_paths_per_rcvr + p]; */
	/* 		if(!shd_path->enabled && p == receiver->return_path_idx) { */
	/* 			receiver->return_path_idx++; */
	/* 		} */
	/* 		if(shd_path->replaced) { */
	/* 			shd_path->replaced = false; */
	/* 			// assert that chunk length fits into packet with new header */
	/* 			if(shd_path->payloadlen < (int)tx_state->chunklen + rbudp_headerlen) { */
	/* 				fprintf(stderr, */
	/* 				        "cannot use path %d for receiver %d: header too big, chunk does not fit into payload\n", p, */
	/* 				        r); */
	/* 				receiver->paths[p].enabled = false; */
	/* 				continue; */
	/* 			} */
	/* 			memcpy(&receiver->paths[p], shd_path, sizeof(struct hercules_path)); */

	/* 			atomic_store(&receiver->paths[p].next_handshake_at, */
	/* 			             UINT64_MAX); // by default do not send a new handshake */
	/* 			if(p == receiver->return_path_idx) { */
	/* 				atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure handshake_rtt is adapted */
	/* 				// don't trigger RTT estimate on other paths, as it will be triggered by the ACK on the new return path */
	/* 				replaced_return_path = true; */
	/* 			} */
	/* 			// reset PCC state */
	/* 			if(!replaced_return_path && receiver->cc_states != NULL) { */
	/* 				terminate_ccontrol(&receiver->cc_states[p]); */
	/* 				continue_ccontrol(&receiver->cc_states[p]); */
	/* 				atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure mi_duration is set */
	/* 			} */
	/* 		} else { */
	/* 			if(p == receiver->return_path_idx) { */
	/* 				atomic_store(&receiver->paths[p].next_handshake_at, now); // make sure handshake_rtt is adapted */
	/* 				// don't trigger RTT estimate on other paths, as it will be triggered by the ACK on the new return path */
	/* 				replaced_return_path = true; */
	/* 			} */
	/* 			if(receiver->cc_states != NULL && receiver->paths[p].enabled != shd_path->enabled) { */
	/* 				if(shd_path->enabled) { // reactivate PCC */
	/* 					if(receiver->cc_states != NULL) { */
	/* 						double rtt = receiver->cc_states[p].rtt; */
	/* 						double mi_duration = receiver->cc_states[p].pcc_mi_duration; */
	/* 						continue_ccontrol(&receiver->cc_states[p]); */
	/* 						receiver->cc_states[p].rtt = rtt; */
	/* 						receiver->cc_states[p].pcc_mi_duration = mi_duration; */
	/* 					} */
	/* 				} else { // deactivate PCC */
	/* 					terminate_ccontrol(&receiver->cc_states[p]); */
	/* 				} */
	/* 			} */
	/* 			receiver->paths[p].enabled = shd_path->enabled; */
	/* 		} */
	/* 	} */
	/* } */
}


static void claim_tx_frames(struct hercules_server *server, struct hercules_interface *iface, u64 *addrs, size_t num_frames)
{
	pthread_spin_lock(&iface->umem->lock);
	size_t reserved = frame_queue__cons_reserve(&iface->umem->available_frames, num_frames);
	while(reserved != num_frames) {
		// When we're not getting any frames, we might need to...
		kick_all_tx(server, iface);
		reserved = frame_queue__cons_reserve(&iface->umem->available_frames, num_frames);
		/* debug_printf("reserved %ld, wanted %ld", reserved, num_frames); */
		// XXX FIXME
		struct hercules_session *s = atomic_load(&server->session_tx);
		if(!s || atomic_load(&s->state) != SESSION_STATE_RUNNING) {
			debug_printf("STOP");
			pthread_spin_unlock(&iface->umem->lock);
			return;
		}
	}

	for(size_t i = 0; i < num_frames; i++) {
		addrs[i] = frame_queue__cons_fetch(&iface->umem->available_frames, i);
	}
	frame_queue__pop(&iface->umem->available_frames, num_frames);
	pthread_spin_unlock(&iface->umem->lock);
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

static inline void tx_handle_send_queue_unit_for_iface(struct sender_state *tx_state, struct xsk_socket_info *xsk,
													   int ifid, u64 frame_addrs[SEND_QUEUE_ENTRIES_PER_UNIT],
													   struct send_queue_unit *unit)
{
	u32 num_chunks_in_unit = 0;
	for(u32 i = 0; i < SEND_QUEUE_ENTRIES_PER_UNIT; i++) {
		if(unit->paths[i] == UINT8_MAX) {
			break;
		}
		struct hercules_path *path = &tx_state->paths[unit->paths[i]];
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
		const struct hercules_path *path = &tx_state->paths[unit->paths[i]];
		if(path->ifid != ifid) {
			continue;
		}
		const u32 chunk_idx = unit->chunk_idx[i];
		const size_t chunk_start = (size_t)chunk_idx * tx_state->chunklen;
		const size_t len = umin64(tx_state->chunklen, tx_state->filesize - chunk_start);

		void *pkt = prepare_frame(xsk, frame_addrs[current_frame], idx + current_frame, path->framelen);
		frame_addrs[current_frame] = -1;
		current_frame++;
		void *rbudp_pkt = mempcpy(pkt, path->header.header, path->headerlen);

#ifdef RANDOMIZE_FLOWID
                short *flowId = (short *)&((char *)pkt)[44]; // ethernet hdr (14), ip hdr (20), udp hdr (8), offset of flowId in scion hdr
                // XXX ^ ignores first 4 bits of flowId
                *flowId = atomic_fetch_add(&flowIdCtr, 1);
#endif
		u8 track_path = PCC_NO_PATH; // put path_idx iff PCC is enabled
		sequence_number seqnr = 0;
		if(tx_state->cc_states != NULL) {
			track_path = unit->paths[i];
			seqnr = atomic_fetch_add(&tx_state->cc_states[unit->paths[i]].last_seqnr, 1);
		}
		fill_rbudp_pkt(rbudp_pkt, chunk_idx, track_path, seqnr, tx_state->mem + chunk_start, len, path->payloadlen);
		stitch_checksum(path, path->header.checksum, pkt);
	}
	xsk_ring_prod__submit(&xsk->tx, num_chunks_in_unit);
}

static inline void tx_handle_send_queue_unit(struct hercules_server *server, struct sender_state *tx_state, struct xsk_socket_info *xsks[],
											 u64 frame_addrs[][SEND_QUEUE_ENTRIES_PER_UNIT],
											 struct send_queue_unit *unit)
{

	for(int i = 0; i < server->num_ifaces; i++) {
		tx_handle_send_queue_unit_for_iface(tx_state, xsks[i], server->ifaces[i].ifid, frame_addrs[i], unit);
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

		unit->rcvr[num_chunks_in_unit] = rcvr_by_chunk[chk];
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
									  u64 frame_addrs[][SEND_QUEUE_ENTRIES_PER_UNIT])
{
	for(int i = 0; i < server->num_ifaces; i++) {
		int num_frames;
		for(num_frames = 0; num_frames < SEND_QUEUE_ENTRIES_PER_UNIT; num_frames++) {
			if(frame_addrs[i][num_frames] != (u64) -1) {
				break;
			}
		}
		claim_tx_frames(server, &server->ifaces[i], frame_addrs[i], num_frames);
	}
}

// Compute rate limit for the path currently marked active
static u32 compute_max_chunks_current_path(struct sender_state *tx_state) {
	u32 allowed_chunks = 0;
	u64 now = get_nsecs();

	if (!tx_state->paths[tx_state->path_index].enabled) {
		return 0;  // if a receiver does not have any enabled paths, we can
				   // actually end up here ... :(
	}

	if (tx_state->cc_states != NULL) {	// use PCC
		struct ccontrol_state *cc_state =
			&tx_state->cc_states[tx_state->path_index];
		/* debug_printf("path idx %d", tx_state->receiver[0].path_index); */
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

static void prepare_rcvr_paths(struct sender_state *tx_state, u8 *rcvr_path) {
	rcvr_path[0] = tx_state->path_index;
}

// Mark the next available path as active
static void iterate_paths(struct sender_state *tx_state) {
	if (tx_state->num_paths == 0) {
		return;
	}
	u32 prev_path_index =
		tx_state->path_index;  // we need this to break the loop if all paths
							   // are disabled
	if (prev_path_index >= tx_state->num_paths) {
		prev_path_index = 0;
	}
	do {
		tx_state->path_index = (tx_state->path_index + 1) % tx_state->num_paths;
	} while (!tx_state->paths[tx_state->path_index].enabled &&
			 tx_state->path_index != prev_path_index);
}

static void terminate_cc(const struct sender_state *tx_state) {
	for (u32 i = 0; i < tx_state->num_paths; i++) {
		terminate_ccontrol(&tx_state->cc_states[i]);
	}
}

static void kick_cc(struct sender_state *tx_state) {
	if (tx_state->finished) {
		return;
	}
	for (u32 p = 0; p < tx_state->num_paths; p++) {
		kick_ccontrol(&tx_state->cc_states[p]);
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
                               u64 *wait_until, u32 num_chunks)
{
	u32 num_chunks_prepared = 0;
	u32 chunk_idx = tx_state->prev_chunk_idx;
	/* debug_printf("n chunks %d", num_chunks); */
	for(; num_chunks_prepared < num_chunks; num_chunks_prepared++) {
		/* debug_printf("prepared %d/%d chunks", num_chunks_prepared, num_chunks); */
		chunk_idx = bitset__scan_neg(&tx_state->acked_chunks, chunk_idx);
		if(chunk_idx == tx_state->total_chunks) {
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
										  int max_rate_limit, char *mem,
										  const struct hercules_app_addr *dests,
										  struct hercules_path *paths,
										  u32 num_dests, const int num_paths,
										  u32 max_paths_per_dest) {
	u64 total_chunks = (filesize + chunklen - 1) / chunklen;
	if (total_chunks >= UINT_MAX) {
		fprintf(stderr,
				"File too big, not enough chunks available (chunks needed: "
				"%llu, chunks available: %u)\n",
				total_chunks, UINT_MAX - 1);
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
	tx_state->mem = mem;
	tx_state->rate_limit = max_rate_limit;
	tx_state->start_time = 0;
	tx_state->end_time = 0;

	bitset__create(&tx_state->acked_chunks, tx_state->total_chunks);
	tx_state->path_index = 0;
	tx_state->handshake_rtt = 0;
	tx_state->num_paths = num_paths;
	tx_state->paths = paths;
	tx_state->session->peer = *dests;
	update_hercules_tx_paths(tx_state);
	return tx_state;
}

static void destroy_tx_state(struct sender_state *tx_state) {
	bitset__destroy(&tx_state->acked_chunks);
	free(tx_state->paths);
	free(tx_state);
}

// (Re)send HS if needed
static void tx_retransmit_initial(struct hercules_server *server, u64 now) {
	struct hercules_session *session_tx = server->session_tx;
	if (session_tx && session_tx->state == SESSION_STATE_PENDING) {
		if (now >
			session_tx->last_pkt_sent + session_hs_retransmit_interval) {
			struct sender_state *tx_state = session_tx->tx_state;
			tx_send_initial(server, &tx_state->paths[tx_state->return_path_idx],
							tx_state->filename, tx_state->filesize,
							tx_state->chunklen, now, 0, session_tx->etherlen, true, true);
			session_tx->last_pkt_sent = now;
		}
	}
}

static void tx_handle_hs_confirm(struct hercules_server *server,
							  struct rbudp_initial_pkt *parsed_pkt) {
	struct hercules_session *session_tx = server->session_tx;
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
			u64 now = get_nsecs();
			tx_state->handshake_rtt = now - parsed_pkt->timestamp;
			// TODO where to get rate limit?
			// below is ~in Mb/s (but really pps)
			/* u32 rate = 2000e3; // 20 Gbps */
			u32 rate = 100; // 1 Mbps
			debug_printf("rate limit %u", rate);
			tx_state->cc_states = init_ccontrol_state(
				rate, tx_state->total_chunks,
				tx_state->num_paths, tx_state->num_paths,
				tx_state->num_paths);
			ccontrol_update_rtt(&tx_state->cc_states[0],
								tx_state->handshake_rtt);
			fprintf(stderr,
					"[receiver %d] [path 0] handshake_rtt: "
					"%fs, MI: %fs\n",
					0, tx_state->handshake_rtt / 1e9,
					tx_state->cc_states[0].pcc_mi_duration);

			// make sure we later perform RTT estimation
			// on every enabled path
			tx_state->paths[0].next_handshake_at =
				UINT64_MAX;	 // We just completed the HS for this path
			for (u32 p = 1; p < tx_state->num_paths; p++) {
				tx_state->paths[p].next_handshake_at = now;
			}
		}
		session_tx->state = SESSION_STATE_WAIT_CTS;
		return;
	}

	if (session_tx != NULL &&
		session_tx->state == SESSION_STATE_RUNNING) {
		struct sender_state *tx_state = session_tx->tx_state;
		// This is a reply to some handshake we sent during an already
		// established session (e.g. to open a new path)
		u64 now = get_nsecs();
		if (server->enable_pcc) {
			ccontrol_update_rtt(&tx_state->cc_states[parsed_pkt->path_index],
								now - parsed_pkt->timestamp);
		}
		tx_state->paths[parsed_pkt->path_index].next_handshake_at = UINT64_MAX;

		// We have a new return path, redo handshakes on all other paths
		if (parsed_pkt->flags & HANDSHAKE_FLAG_SET_RETURN_PATH){
			tx_state->handshake_rtt = now - parsed_pkt->timestamp;
			for (u32 p = 0; p < tx_state->num_paths; p++){
				if (p != parsed_pkt->path_index && tx_state->paths[p].enabled){
					tx_state->paths[p].next_handshake_at = now;
					tx_state->cc_states[p].pcc_mi_duration = DBL_MAX;
					tx_state->cc_states[p].rtt = DBL_MAX;
				}
			}
		}
		return;
	}
	// In other cases we just drop the packet
	debug_printf("Dropping HS confirm packet, was not expecting one");
}

// Map the provided file into memory for reading. Returns pointer to the mapped
// area, or null on error.
static char *tx_mmap(char *fname, size_t *filesize) {
	int f = open(fname, O_RDONLY);
	if (f == -1) {
		return NULL;
	}
	struct stat stat;
	int ret = fstat(f, &stat);
	if (ret) {
		close(f);
		return NULL;
	}
	const size_t fsize = stat.st_size;
	char *mem = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, f, 0);
	if (mem == MAP_FAILED) {
		close(f);
		return NULL;
	}
	close(f);
	*filesize = fsize;
	return mem;
}
/// OK PCC
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
	for(u32 cur_path = 0; cur_path < tx_state->num_paths; cur_path++) {
		struct ccontrol_state *cc_state = &tx_state->cc_states[cur_path];
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
/// workers
struct tx_send_p_args {
	struct hercules_server *server;
	struct xsk_socket_info *xsks[];
};

// Read chunk ids from the send queue, fill in packets accorindgly and actually
// send them. This is the function run by the TX worker thread(s).
static void tx_send_p(void *arg) {
	struct tx_send_p_args *args = arg;
	struct hercules_server *server = args->server;
	while (1) {
		struct hercules_session *session_tx = atomic_load(&server->session_tx);
		if (session_tx == NULL ||
			atomic_load(&session_tx->state) != SESSION_STATE_RUNNING) {
			kick_tx_server(server);	 // flush any pending packets
			continue;
		}
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
		allocate_tx_frames(server, frame_addrs);
		tx_handle_send_queue_unit(server, session_tx->tx_state, args->xsks,
								  frame_addrs, &unit);
		kick_tx_server(
			server);  // FIXME should not be needed and probably inefficient
	}
}

// Send ACKs to the sender. Runs in its own thread.
static void rx_trickle_acks(void *arg) {
	struct hercules_server *server = arg;
	while (1) {
		struct hercules_session *session_rx = atomic_load(&server->session_rx);
		if (session_rx != NULL && session_rx->state == SESSION_STATE_RUNNING) {
			struct receiver_state *rx_state = session_rx->rx_state;
			// XXX: data races in access to shared rx_state!
			atomic_store(&rx_state->last_pkt_rcvd, get_nsecs());
			if (atomic_load(&rx_state->last_pkt_rcvd) +
					umax64(100 * ACK_RATE_TIME_MS * 1e6,
						   3 * rx_state->handshake_rtt) <
				get_nsecs()) {
				// Transmission timed out
				quit_session(session_rx, SESSION_ERROR_TIMEOUT);
			}
			rx_send_acks(server, rx_state);
			if (rx_received_all(
					rx_state)) {  // TODO move this check to ack receive?
				debug_printf("Received all, done.");
				quit_session(session_rx, SESSION_ERROR_OK);
				rx_send_acks(server, rx_state);
			}
		}
		sleep_nsecs(ACK_RATE_TIME_MS * 1e6);
	}
}

// Send NACKs to the sender. Runs in its own thread.
static void rx_trickle_nacks(void *arg) {
	struct hercules_server *server = arg;
	while (1) {
		struct hercules_session *session_rx = atomic_load(&server->session_rx);
		if (session_rx != NULL && session_rx->state == SESSION_STATE_RUNNING) {
			u32 ack_nr = 0;
			struct receiver_state *rx_state = session_rx->rx_state;
			// TODO remove this inner loop?
			while (rx_state->session->state == SESSION_STATE_RUNNING &&
				   !rx_received_all(rx_state)) {
				u64 ack_round_start = get_nsecs();
				rx_send_nacks(server, rx_state, ack_round_start, ack_nr);
				u64 ack_round_end = get_nsecs();
				if (ack_round_end >
					ack_round_start + rx_state->handshake_rtt * 1000 / 4) {
					/* fprintf(stderr, "NACK send too slow (took %lld of %ld)\n", */
					/* 		ack_round_end - ack_round_start, */
					/* 		rx_state->handshake_rtt * 1000 / 4); */
				} else {
					sleep_until(ack_round_start +
								rx_state->handshake_rtt * 1000 / 4);
				}
				ack_nr++;
			}
		}
	}
}

// Receive data packets on the XDP sockets. Runs in the RX worker thread(s).
static void rx_p(void *arg) {
	struct rx_p_args *args = arg;
	struct hercules_server *server = args->server;
	int num_ifaces = server->num_ifaces;
	u32 i = 0;
	while (1) {
		struct hercules_session *session_rx = atomic_load(&server->session_rx);
		if (session_rx != NULL && session_rx->state == SESSION_STATE_RUNNING) {
			rx_receive_batch(session_rx->rx_state, args->xsks[i % num_ifaces]);
			i++;
		}
		else {
			// Even though we don't currently have a running session, we might
			// not have processed all received packets before stopping the
			// previous session (or they might still be in flight). Drain any
			// received packets to avoid erroneously assigning them to the next
			// session.
			rx_receive_and_drop(args->xsks[i % num_ifaces]);
			i++;
		}
	}
}

// Check if the monitor has new transfer jobs available and, if so, start one
static void new_tx_if_available(struct hercules_server *server) {
	char fname[1000];
	memset(fname, 0, 1000);
	int count;
	u16 jobid;
	u16 mtu;
	struct hercules_app_addr dest;

	pthread_spin_lock(&usock_lock);
	int ret = monitor_get_new_job(usock, fname, &jobid, &dest, &mtu);
	pthread_spin_unlock(&usock_lock);
	if (!ret) {
		return;
	}
	debug_printf("new job: %s", fname);
	if (HERCULES_MAX_HEADERLEN + sizeof(struct rbudp_initial_pkt) +
			rbudp_headerlen >
		(size_t)mtu) {
		debug_printf("supplied MTU too small");
		// TODO update_job with err
		return;
	}
	if (mtu > HERCULES_MAX_PKTSIZE){
		debug_printf("supplied MTU too large");
		// TODO update_job with err
		return;
	}
	size_t filesize;
	char *mem = tx_mmap(fname, &filesize);
	if (mem == NULL){
		debug_printf("mmap failed");
		// TODO update_job with err
		return;
	}
	struct hercules_session *session = make_session(server);
	if (session == NULL){
		// TODO update_job with err
		debug_printf("error creating session");
		munmap(mem, filesize);
		return;
	}
	session->state = SESSION_STATE_PENDING;
	session->etherlen = mtu;
	session->jobid = jobid;

	int n_paths;
	struct hercules_path *paths;
	ret = monitor_get_paths(usock, jobid, &n_paths, &paths);
	if (!ret || n_paths == 0){
		debug_printf("error getting paths");
		munmap(mem, filesize);
		/* destroy_session(session); */ // FIXME
										// TODO update job err
		return;
	}
	// TODO free paths
	debug_printf("received %d paths", n_paths);

	// TODO If the paths don't have the same header length this does not work:
	// If the first path has a shorter header than the second, chunks won't fit
	// on the second path
	u32 chunklen = paths[0].payloadlen - rbudp_headerlen;
	atomic_store(&server->session_tx, session);
	struct sender_state *tx_state = init_tx_state(
		server->session_tx, filesize, chunklen, server->rate_limit, mem,
		&session->peer, paths, 1, n_paths,
		server->max_paths);
	strncpy(tx_state->filename, fname, 99);
	server->session_tx->tx_state = tx_state;
}

// Remove and free finished sessions
static void cleanup_finished_sessions(struct hercules_server *server, u64 now) {
	// Wait for twice the session timeout before removing the finished
	// session (and thus before accepting new sessions). This ensures the
	// other party has also quit or timed out its session and won't send
	// packets that would then be mixed into future sessions.
	// XXX This depends on both endpoints sharing the same timeout value,
	// which is not negotiated but defined at the top of this file.
	struct hercules_session *session_tx = atomic_load(&server->session_tx);
	if (session_tx && session_tx->state == SESSION_STATE_DONE) {
		if (now > session_tx->last_pkt_rcvd + session_timeout * 2) {
			monitor_update_job(usock, session_tx->jobid, session_tx->state,
							   session_tx->error, 0, 0); // FIXME 0 0
			struct hercules_session *current = server->session_tx;
			atomic_store(&server->session_tx, NULL);
			fprintf(stderr, "Cleaning up TX session...\n");
			// At this point we don't know if some other thread still has a
			// pointer to the session that it might dereference, so we cannot
			// safely free it. So, we record the pointer and defer freeing it
			// until after the next session has completed. At that point, no
			// references to the deferred session should be around, so we then
			// free it.
			// XXX Is this really good enough?
			destroy_session_tx(server->deferred_tx);
			server->deferred_tx = current;
		}
	}
	struct hercules_session *session_rx = atomic_load(&server->session_rx);
	if (session_rx && session_rx->state == SESSION_STATE_DONE) {
		if (now > session_rx->last_pkt_rcvd + session_timeout * 2) {
			struct hercules_session *current = server->session_rx;
			atomic_store(&server->session_rx, NULL);
			fprintf(stderr, "Cleaning up RX session...\n");
			// See the note above on deferred freeing
			destroy_session_rx(server->deferred_rx);
			server->deferred_rx = current;
		}
	}
}

// Time out if no packets received for a while
static void mark_timed_out_sessions(struct hercules_server *server, u64 now) {
	struct hercules_session *session_tx = server->session_tx;
	if (session_tx && session_tx->state != SESSION_STATE_DONE) {
		if (now > session_tx->last_pkt_rcvd + session_timeout) {
			quit_session(session_tx, SESSION_ERROR_TIMEOUT);
			debug_printf("Session (TX) timed out!");
		}
	}
	struct hercules_session *session_rx = server->session_rx;
	if (session_rx && session_rx->state != SESSION_STATE_DONE) {
		if (now > session_rx->last_pkt_rcvd + session_timeout) {
			quit_session(session_rx, SESSION_ERROR_TIMEOUT);
			debug_printf("Session (RX) timed out!");
		}
		else if (new > session_rx->last_new_pkt_rcvd + session_stale_timeout){
			quit_session(session_tx, SESSION_ERROR_STALE);
			debug_printf("Session (RX) stale!")
		}
	}
}

static void tx_update_paths(struct hercules_server *server) {
	struct hercules_session *session_tx = server->session_tx;
	if (session_tx && session_tx->state == SESSION_STATE_RUNNING) {
		int n_paths;
		struct hercules_path *paths;
		bool ret =
			monitor_get_paths(usock, session_tx->jobid, &n_paths, &paths);
		if (!ret) {
			debug_printf("error getting paths");
			return;
		}
		debug_printf("received %d paths", n_paths);
		if (n_paths == 0){
			free(paths);
			quit_session(session_tx, SESSION_ERROR_NO_PATHS);
			return;
		}
		// XXX doesn't this break if we get more paths and the update is not
		// atomic?
		session_tx->tx_state->num_paths = n_paths;
		session_tx->tx_state->paths = paths;
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

static void print_session_stats(struct hercules_server *server,
								struct prints *p) {
	u64 now = get_nsecs();
	if (now < p->ts + 500e6) {
		return;
	}
	u64 tdiff = now - p->ts;
	p->ts = now;

	struct hercules_session *session_tx = server->session_tx;
	if (session_tx && session_tx->state != SESSION_STATE_DONE) {
		u32 sent_now = session_tx->tx_npkts;
		u32 acked_count = session_tx->tx_state->acked_chunks.num_set;
		u32 total = session_tx->tx_state->acked_chunks.num;
		double send_rate_pps = (sent_now - p->tx_sent) / ((double)tdiff / 1e9);
		p->tx_sent = sent_now;
		double send_rate =
			8 * send_rate_pps * server->session_tx->tx_state->chunklen / 1e6;
		fprintf(stderr, "(TX) Chunks: %u/%u, rx: %ld, tx:%ld, rate %.2f Mbps\n",
				acked_count, total, session_tx->rx_npkts, session_tx->tx_npkts,
				send_rate);
	}

	struct hercules_session *session_rx = server->session_rx;
	if (session_rx && session_rx->state != SESSION_STATE_DONE) {
		u32 begin = bitset__scan_neg(&session_rx->rx_state->received_chunks, 0);
		u32 rec_count = session_rx->rx_state->received_chunks.num_set;
		u32 total = session_rx->rx_state->received_chunks.num;
		u32 rcvd_now = session_rx->rx_npkts;
		double recv_rate_pps =
			(rcvd_now - p->rx_received) / ((double)tdiff / 1e9);
		p->rx_received = rcvd_now;
		double recv_rate =
			8 * recv_rate_pps * server->session_rx->rx_state->chunklen / 1e6;
		fprintf(stderr, "(RX) Chunks: %u/%u, rx: %ld, tx:%ld, rate %.2f Mbps\n",
				rec_count, total, session_rx->rx_npkts, session_rx->tx_npkts,
				recv_rate);
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
	struct prints prints = {.rx_received=0, .ts=0, .tx_sent=0};
	while (1) {	 // event handler thread loop
		u64 now = get_nsecs();
		/* if (now > lastpoll + 1e9){ */
		// XXX run the following every n seconds or every n socket reads?
		if (server->session_tx == NULL) {
			new_tx_if_available(server);
		}
		mark_timed_out_sessions(server, now);
		cleanup_finished_sessions(server, now);
		tx_retransmit_initial(server, now);
#ifdef PRINT_STATS
		print_session_stats(server, &prints);
#endif
		if (now > lastpoll + 10e9){
			tx_update_paths(server);
			lastpoll = now;
		}
		/* 	lastpoll = now; */
		/* } */

		// XXX This is a bit of a hack: We want to handle received packets more
		// frequently than we poll the monitor or check for expired sessions, so
		// try to receive 100 times (non-blocking) before doing anything else.
		for (int i = 0; i < 100; i++) {
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

			const char *rbudp_pkt =
				parse_pkt(server, buf, len, true, &scionaddrhdr, &udphdr);
			if (rbudp_pkt == NULL) {
				continue;
			}

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
						struct rbudp_initial_pkt *parsed_pkt;
						rbudp_check_initial(cp,
											rbudp_len - rbudp_headerlen,
											&parsed_pkt);
						if (parsed_pkt->flags & HANDSHAKE_FLAG_HS_CONFIRM) {
							// This is a confirmation for a handshake packet
							// we sent out earlier
							debug_printf("HS confirm packet");
							tx_handle_hs_confirm(server, parsed_pkt);
							break;	// Make sure we don't process this further
						}
						// Otherwise, we process and reflect the packet
						if (server->session_rx != NULL &&
							server->session_rx->state ==
								SESSION_STATE_RUNNING) {
							if (!(parsed_pkt->flags &
								  HANDSHAKE_FLAG_NEW_TRANSFER)) {
								// This is a handshake that tries to open a new
								// path for the running transfer
								rx_handle_initial(
									server, server->session_rx->rx_state,
									parsed_pkt, buf, addr.sll_ifindex,
									rbudp_pkt + rbudp_headerlen, len);
							}
						}
						if (server->session_rx == NULL &&
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
								server->session_rx = session;
								session->state = SESSION_STATE_NEW;
								struct receiver_state *rx_state = make_rx_state(
									session, parsed_pkt->name, parsed_pkt->name_len,
									parsed_pkt->filesize, parsed_pkt->chunklen,
									parsed_pkt->etherlen, false);
								session->rx_state = rx_state;
								rx_handle_initial(server, rx_state, parsed_pkt,
												  buf, addr.sll_ifindex,
												  rbudp_pkt + rbudp_headerlen,
												  len);
								rx_send_cts_ack(server, rx_state);
								server->session_rx->state =
									SESSION_STATE_RUNNING;
							}
						}
						break;

					case CONTROL_PACKET_TYPE_ACK:
						if (control_pkt_payloadlen < ack__len(&cp->payload.ack)){
							debug_printf("ACK packet too short");
							break;
						}
						if (server->session_tx != NULL &&
							server->session_tx->state ==
								SESSION_STATE_WAIT_CTS) {
							if (cp->payload.ack.num_acks == 0) {
								debug_printf("CTS received");
								atomic_store(&server->session_tx->state,
											 SESSION_STATE_RUNNING);
							}
						}
						if (server->session_tx != NULL &&
							server->session_tx->state ==
								SESSION_STATE_RUNNING) {
							tx_register_acks(
								&cp->payload.ack,
								server->session_tx->tx_state);
							count_received_pkt(server->session_tx, h->path);
							atomic_store(&server->session_tx->last_pkt_rcvd, get_nsecs());
							if (tx_acked_all(server->session_tx->tx_state)) {
								debug_printf("TX done, received all acks");
								quit_session(server->session_tx,
											 SESSION_ERROR_OK);
							}
						}
						break;

					case CONTROL_PACKET_TYPE_NACK:
						if (control_pkt_payloadlen <
							ack__len(&cp->payload.ack)) {
							debug_printf("NACK packet too short");
							break;
						}
						if (server->session_tx != NULL &&
							server->session_tx->state ==
								SESSION_STATE_RUNNING) {
							count_received_pkt(server->session_tx, h->path);
							nack_trace_push(cp->payload.ack.timestamp,
											cp->payload.ack.ack_nr);
							tx_register_nacks(
								&cp->payload.ack,
								&server->session_tx->tx_state
									->cc_states[h->path]);
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
			if (server->session_tx && server->session_tx->tx_state->cc_states){
				pcc_monitor(server->session_tx->tx_state);
			}
		}
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
  while (1) {
    /* pthread_spin_lock(&server->biglock); */
    pop_completion_rings(server);
    u32 chunks[BATCH_SIZE];
    u8 chunk_rcvr[BATCH_SIZE];
    struct hercules_session *session_tx = atomic_load(&server->session_tx);
    if (session_tx != NULL &&
        atomic_load(&session_tx->state) == SESSION_STATE_RUNNING) {
      struct sender_state *tx_state = session_tx->tx_state;
      /* debug_printf("Start transmit round"); */
      tx_state->prev_rate_check = get_nsecs();

      pop_completion_rings(server);
      send_path_handshakes(server, tx_state);
      u64 next_ack_due = 0;

      // in each iteration, we send packets on a single path to each receiver
      // collect the rate limits for each active path
      u32 allowed_chunks = compute_max_chunks_current_path(tx_state);

      if (allowed_chunks ==
          0) { // we hit the rate limits on every path; switch paths
        iterate_paths(tx_state);
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
        // for each receiver, we prepare up to max_chunks_per_rcvr[r] chunks to
        // send
        u32 cur_num_chunks = prepare_rcvr_chunks(
            tx_state, 0, &chunks[num_chunks], &chunk_rcvr[num_chunks], now,
            &ack_due, allowed_chunks);
        num_chunks += cur_num_chunks;
        if (tx_state->finished) {
          if (tx_state->cc_states) {
            terminate_cc(tx_state);
            kick_cc(tx_state);
          }
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
        u32 path_idx = tx_state->path_index;
        if (tx_state->cc_states != NULL) {
          struct ccontrol_state *cc_state = &tx_state->cc_states[path_idx];
		  // FIXME allowed_chunks below is not correct (3x)
          atomic_fetch_add(&cc_state->mi_tx_npkts, allowed_chunks);
          atomic_fetch_add(&cc_state->total_tx_npkts, allowed_chunks);
          if (pcc_has_active_mi(cc_state, now)) {
            atomic_fetch_add(&cc_state->mi_tx_npkts_monitored,
                             allowed_chunks);
          }
        }
      }

      iterate_paths(tx_state);

      if (now < next_ack_due) {
        // XXX if the session vanishes in the meantime, we might wait
        // unnecessarily
        sleep_until(next_ack_due);
      }
    }
  }

  return NULL;
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

  xdp_setup(server);

  // Start event receiver thread
  debug_printf("Starting event receiver thread");
  pthread_t events = start_thread(NULL, events_p, server);

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

  while (1) {
    // XXX STOP HERE
    // FIXME make this thread do something
  }
  join_thread(server, tx_p_thread);
}

void usage(){
	fprintf(stderr, "usage: ?? TODO\n");
	exit(1);
}

// TODO what's up with multiple interfaces?
#define HERCULES_MAX_INTERFACES 1
int main(int argc, char *argv[]) {
  // Options:
  // -i interface
  // -l listen address
  // -z XDP zerocopy mode
  // -q queue
  // -t TX worker threads
  // -r RX worker threads
  unsigned int if_idxs[HERCULES_MAX_INTERFACES]; // XXX 10 should be enough
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

  usock = monitor_bind_daemon_socket();
  if (usock == 0) {
    fprintf(stderr, "Error binding daemon socket\n");
    exit(1);
  }

  struct hercules_server *server =
      hercules_init_server(if_idxs, n_interfaces, listen_addr, queue, xdp_mode, rx_threads, false);

  hercules_main(server);
}

/// Local Variables:
/// outline-regexp: "/// "
/// eval:(outline-minor-mode 1)
/// End:
