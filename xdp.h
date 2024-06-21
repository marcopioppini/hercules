#ifndef HERCULES_XDP_H_
#define HERCULES_XDP_H_

#include "hercules.h"

// Remove the XDP program loaded on all the server's interfaces
void remove_xdp_program(struct hercules_server *server);

// Removes socket and frees xsk
void close_xsk(struct xsk_socket_info *xsk);
//
// Create and configure the UMEM for the given interface using the provided
// buffer and size. Also initializes the UMEM's frame queue.
struct xsk_umem_info *xsk_configure_umem_server(struct hercules_server *server,
												u32 ifidx, void *buffer,
												u64 size);

void destroy_umem(struct xsk_umem_info *umem);

int submit_initial_rx_frames(struct hercules_server *server,
							 struct xsk_umem_info *umem);

int submit_initial_tx_frames(struct hercules_server *server,
							 struct xsk_umem_info *umem);

// Configure the NIC(s) to send incoming packets to the queue Hercules is using.
int configure_rx_queues(struct hercules_server *server);

// Remove ethtool rules previously set by configure_rx_queues
int unconfigure_rx_queues(struct hercules_server *server);

int load_bpf(const void *prgm, ssize_t prgm_size, struct bpf_object **obj);

int set_bpf_prgm_active(struct hercules_server *server,
						struct hercules_interface *iface, int prog_fd);

int xsk_map__add_xsk(struct hercules_server *server, xskmap map, int index,
					 struct xsk_socket_info *xsk);

int load_xsk_redirect_userspace(struct hercules_server *server,
								struct worker_args *args[], int num_threads);

int xdp_setup(struct hercules_server *server);

// Remove xdp program from interface and ethtool rules
void xdp_teardown(struct hercules_server *server);

#endif	// HERCULES_XDP_H_
