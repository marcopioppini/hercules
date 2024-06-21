#include "xdp.h"

#include <asm-generic/errno-base.h>
#include <unistd.h>

#include "bpf/src/bpf.h"
#include "bpf_prgms.h"
#include "hercules.h"

void remove_xdp_program(struct hercules_server *server) {
	for (int i = 0; i < server->num_ifaces; i++) {
		u32 curr_prog_id = 0;
		if (bpf_get_link_xdp_id(server->ifaces[i].ifid, &curr_prog_id,
								server->config.xdp_flags)) {
			printf("bpf_get_link_xdp_id failed\n");
			exit(EXIT_FAILURE);
		}
		if (server->ifaces[i].prog_id == curr_prog_id)
			bpf_set_link_xdp_fd(server->ifaces[i].ifid, -1,
								server->config.xdp_flags);
		else if (!curr_prog_id)
			printf("couldn't find a prog id on a given interface\n");
		else
			printf("program on interface changed, not removing\n");
	}
}

void close_xsk(struct xsk_socket_info *xsk) {
	xsk_socket__delete(xsk->xsk);
	free(xsk);
}

struct xsk_umem_info *xsk_configure_umem_server(struct hercules_server *server,
												u32 ifidx, void *buffer,
												u64 size) {
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		return NULL;
	}

	ret =
		xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
	if (ret) {
		return NULL;
	}

	umem->buffer = buffer;
	umem->iface = &server->ifaces[ifidx];
	// The number of slots in the umem->available_frames queue needs to be
	// larger than the number of frames in the loop, pushed in
	// submit_initial_tx_frames() (assumption in pop_completion_ring() and
	// handle_send_queue_unit())
	ret = frame_queue__init(&umem->available_frames,
							XSK_RING_PROD__DEFAULT_NUM_DESCS);
	if (ret) {
		return NULL;
	}
	pthread_spin_init(&umem->fq_lock, 0);
	pthread_spin_init(&umem->frames_lock, 0);
	return umem;
}

void destroy_umem(struct xsk_umem_info *umem) {
	xsk_umem__delete(umem->umem);
	free(umem->buffer);
	free(umem);
}

int submit_initial_rx_frames(struct hercules_server *server,
							 struct xsk_umem_info *umem) {
	int initial_kernel_rx_frame_count =
		XSK_RING_PROD__DEFAULT_NUM_DESCS - BATCH_SIZE;
	u32 idx;
	int ret =
		xsk_ring_prod__reserve(&umem->fq, initial_kernel_rx_frame_count, &idx);
	if (ret != initial_kernel_rx_frame_count) {
		return EINVAL;
	}
	for (int i = 0; i < initial_kernel_rx_frame_count; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			(XSK_RING_PROD__DEFAULT_NUM_DESCS + i) *
			XSK_UMEM__DEFAULT_FRAME_SIZE;
	xsk_ring_prod__submit(&umem->fq, initial_kernel_rx_frame_count);
	return 0;
}

int submit_initial_tx_frames(struct hercules_server *server,
							 struct xsk_umem_info *umem) {
	// This number needs to be smaller than the number of slots in the
	// umem->available_frames queue (initialized in xsk_configure_umem();
	// assumption in pop_completion_ring() and handle_send_queue_unit())
	int initial_tx_frames = XSK_RING_PROD__DEFAULT_NUM_DESCS - BATCH_SIZE;
	int avail =
		frame_queue__prod_reserve(&umem->available_frames, initial_tx_frames);
	if (initial_tx_frames > avail) {
		debug_printf(
			"trying to push %d initial frames, but only %d slots available",
			initial_tx_frames, avail);
		return EINVAL;
	}
	for (int i = 0; i < avail; i++) {
		frame_queue__prod_fill(&umem->available_frames, i,
							   i * XSK_UMEM__DEFAULT_FRAME_SIZE);
	}
	frame_queue__push(&umem->available_frames, avail);
	return 0;
}

int configure_rx_queues(struct hercules_server *server) {
	for (int i = 0; i < server->num_ifaces; i++) {
		debug_printf("map UDP4 flow to %d.%d.%d.%d to queue %d on interface %s",
					 (u8)(server->config.local_addr.ip),
					 (u8)(server->config.local_addr.ip >> 8u),
					 (u8)(server->config.local_addr.ip >> 16u),
					 (u8)(server->config.local_addr.ip >> 24u),
					 server->ifaces[i].queue, server->ifaces[i].ifname);

		char cmd[1024];
		int cmd_len = snprintf(
			cmd, 1024,
			"ethtool -N %s flow-type udp4 dst-ip %d.%d.%d.%d action %d",
			server->ifaces[i].ifname, (u8)(server->config.local_addr.ip),
			(u8)(server->config.local_addr.ip >> 8u),
			(u8)(server->config.local_addr.ip >> 16u),
			(u8)(server->config.local_addr.ip >> 24u), server->ifaces[i].queue);
		if (cmd_len > 1023) {
			fprintf(stderr,
					"could not configure queue %d on interface %s - command "
					"too long, abort\n",
					server->ifaces[i].queue, server->ifaces[i].ifname);
			unconfigure_rx_queues(server);
			return 1;
		}

		FILE *proc = popen(cmd, "r");
		int rule_id;
		int num_parsed = fscanf(proc, "Added rule with ID %d", &rule_id);
		int ret = pclose(proc);
		if (ret != 0) {
			fprintf(stderr,
					"could not configure queue %d on interface %s, abort\n",
					server->ifaces[i].queue, server->ifaces[i].ifname);
			unconfigure_rx_queues(server);
			return ENODEV;
		}
		if (num_parsed != 1) {
			fprintf(stderr,
					"could not configure queue %d on interface %s, abort\n",
					server->ifaces[i].queue, server->ifaces[i].ifname);
			unconfigure_rx_queues(server);
			return ENODEV;
		}
		server->ifaces[i].ethtool_rule = rule_id;
	}
	return 0;
}

int unconfigure_rx_queues(struct hercules_server *server) {
	int error = 0;
	for (int i = 0; i < server->num_ifaces; i++) {
		if (server->ifaces[i].ethtool_rule >= 0) {
			char cmd[1024];
			int cmd_len = snprintf(cmd, 1024, "ethtool -N %s delete %d",
								   server->ifaces[i].ifname,
								   server->ifaces[i].ethtool_rule);
			server->ifaces[i].ethtool_rule = -1;
			if (cmd_len > 1023) {  // This will never happen as the command to
								   // configure is strictly longer than this one
				fprintf(stderr,
						"could not delete ethtool rule on interface %s - "
						"command too long\n",
						server->ifaces[i].ifname);
				error = EXIT_FAILURE;
				continue;
			}
			int ret = system(cmd);
			if (ret != 0) {
				error = ret;
			}
		}
	}
	return error;
}

int load_bpf(const void *prgm, ssize_t prgm_size, struct bpf_object **obj) {
	static const int log_buf_size = 16 * 1024;
	char log_buf[log_buf_size];
	int prog_fd;

	char tmp_file[] = "/tmp/hrcbpfXXXXXX";
	int fd = mkstemp(tmp_file);
	if (fd < 0) {
		return -errno;
	}
	if (prgm_size != write(fd, prgm, prgm_size)) {
		debug_printf("Could not write bpf file");
		return -EXIT_FAILURE;
	}

	struct bpf_object *_obj;
	if (obj == NULL) {
		obj = &_obj;
	}
	int ret = bpf_prog_load(tmp_file, BPF_PROG_TYPE_XDP, obj, &prog_fd);
	debug_printf("error loading file(%s): %d %s", tmp_file, -ret,
				 strerror(-ret));
	int unlink_ret = unlink(tmp_file);
	if (0 != unlink_ret) {
		fprintf(stderr, "Could not remove temporary file, error: %d",
				unlink_ret);
	}
	if (ret != 0) {
		printf("BPF log buffer:\n%s", log_buf);
		return ret;
	}
	return prog_fd;
}

int set_bpf_prgm_active(struct hercules_server *server,
						struct hercules_interface *iface, int prog_fd) {
	int err =
		bpf_set_link_xdp_fd(iface->ifid, prog_fd, server->config.xdp_flags);
	if (err) {
		return 1;
	}

	int ret = bpf_get_link_xdp_id(iface->ifid, &iface->prog_id,
								  server->config.xdp_flags);
	if (ret) {
		return 1;
	}
	return 0;
}

int xsk_map__add_xsk(struct hercules_server *server, xskmap map, int index,
					 struct xsk_socket_info *xsk) {
	int xsk_fd = xsk_socket__fd(xsk->xsk);
	if (xsk_fd < 0) {
		return 1;
	}
	bpf_map_update_elem(map, &index, &xsk_fd, 0);
	return 0;
}

/*
 * Load a BPF program redirecting IP traffic to the XSK.
 */
int load_xsk_redirect_userspace(struct hercules_server *server,
								struct worker_args *args[], int num_threads) {
	debug_printf("Loading XDP program for redirection");
	for (int i = 0; i < server->num_ifaces; i++) {
		struct bpf_object *obj;
		int prog_fd = load_bpf(bpf_prgm_redirect_userspace,
							   bpf_prgm_redirect_userspace_size, &obj);
		if (prog_fd < 0) {
			return 1;
		}

		// push XSKs
		int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
		if (xsks_map_fd < 0) {
			return 1;
		}
		for (int s = 0; s < num_threads; s++) {
			xsk_map__add_xsk(server, xsks_map_fd, s, args[s]->xsks[i]);
		}

		// push XSKs meta
		int zero = 0;
		int num_xsks_fd = bpf_object__find_map_fd_by_name(obj, "num_xsks");
		if (num_xsks_fd < 0) {
			return 1;
		}
		bpf_map_update_elem(num_xsks_fd, &zero, &num_threads, 0);

		// push local address
		int local_addr_fd = bpf_object__find_map_fd_by_name(obj, "local_addr");
		if (local_addr_fd < 0) {
			return 1;
		}
		bpf_map_update_elem(local_addr_fd, &zero, &server->config.local_addr,
							0);

		set_bpf_prgm_active(server, &server->ifaces[i], prog_fd);
	}
	return 0;
}

int xdp_setup(struct hercules_server *server) {
	for (int i = 0; i < server->num_ifaces; i++) {
		debug_printf("Preparing interface %d", i);
		// Prepare UMEM for XSK sockets
		void *umem_buf;
		int ret = posix_memalign(&umem_buf, getpagesize(),
								 NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
		if (ret) {
			return ENOMEM;
		}
		debug_printf("Allocated umem buffer");

		struct xsk_umem_info *umem = xsk_configure_umem_server(
			server, i, umem_buf, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
		debug_printf("Configured umem");

		server->ifaces[i].xsks =
			calloc(server->n_threads, sizeof(*server->ifaces[i].xsks));
		server->ifaces[i].umem = umem;
		submit_initial_tx_frames(server, umem);
		submit_initial_rx_frames(server, umem);
		debug_printf("umem interface %d %s, queue %d", umem->iface->ifid,
					 umem->iface->ifname, umem->iface->queue);
		if (server->ifaces[i].ifid != umem->iface->ifid) {
			debug_printf(
				"cannot configure XSK on interface %d with queue on interface "
				"%d",
				server->ifaces[i].ifid, umem->iface->ifid);
			return EINVAL;
		}

		// Create XSK sockets
		for (int t = 0; t < server->n_threads; t++) {
			struct xsk_socket_info *xsk;
			xsk = calloc(1, sizeof(*xsk));
			if (!xsk) {
				return ENOMEM;
			}
			xsk->umem = umem;

			struct xsk_socket_config cfg;
			cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
			cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
			cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
			cfg.xdp_flags = server->config.xdp_flags;
			cfg.bind_flags = server->config.xdp_mode;
			ret = xsk_socket__create_shared(
				&xsk->xsk, server->ifaces[i].ifname, server->config.queue,
				umem->umem, &xsk->rx, &xsk->tx, &umem->fq, &umem->cq, &cfg);
			if (ret) {
				return -ret;
			}
			ret = bpf_get_link_xdp_id(server->ifaces[i].ifid,
									  &server->ifaces[i].prog_id,
									  server->config.xdp_flags);
			if (ret) {
				return -ret;
			}
			server->ifaces[i].xsks[t] = xsk;
		}
		server->ifaces[i].num_sockets = server->n_threads;
	}
	for (int t = 0; t < server->n_threads; t++) {
		server->worker_args[t] =
			malloc(sizeof(**server->worker_args) +
				   server->num_ifaces * sizeof(*server->worker_args[t]->xsks));
		if (server->worker_args[t] == NULL) {
			return ENOMEM;
		}
		server->worker_args[t]->server = server;
		server->worker_args[t]->id = t+1;
		for (int i = 0; i < server->num_ifaces; i++) {
			server->worker_args[t]->xsks[i] = server->ifaces[i].xsks[t];
		}
	}

	load_xsk_redirect_userspace(server, server->worker_args, server->n_threads);
	// TODO this is not set anywhere, so it will never run
	if (server->config.configure_queues) {
		configure_rx_queues(server);
	}
	// TODO when/where is this needed?
	// same for rx_state
	/* 	libbpf_smp_rmb(); */
	/* 	session->tx_state = tx_state; */
	/* 	libbpf_smp_wmb(); */
	debug_printf("XSK stuff complete");
	return 0;
}

void xdp_teardown(struct hercules_server *server){
	remove_xdp_program(server);
	unconfigure_rx_queues(server);
}
