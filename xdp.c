#include "xdp.h"

#include <asm-generic/errno-base.h>
#include <linux/if_xdp.h>
#include <unistd.h>
#include <xdp/libxdp.h>

#include "utils.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_prgms.h"
#include "hercules.h"

void remove_xdp_program(struct hercules_server *server) {
	for (int i = 0; i < server->num_ifaces; i++) {
		enum xdp_attach_mode mode = xdp_program__is_attached(
			server->ifaces[i].xdp_prog, server->ifaces[i].ifid);
		if (!mode) {
			fprintf(stderr, "Program not attached on %s?\n",
					server->ifaces[i].ifname);
			continue;
		}
		int err = xdp_program__detach(server->ifaces[i].xdp_prog,
									  server->ifaces[i].ifid, mode, 0);
		char errmsg[1024];
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Error detaching XDP program from %s: %s\n",
					server->ifaces[i].ifname, errmsg);
			continue;
		}
		xdp_program__close(server->ifaces[i].xdp_prog);
		server->ifaces[i].xdp_prog = NULL;
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
	ret = pthread_spin_init(&umem->fq_lock, 0);
	if (ret) {
		return NULL;
	}
	ret = pthread_spin_init(&umem->frames_lock, 0);
	if (ret) {
		return NULL;
	}
	return umem;
}

void destroy_umem(struct xsk_umem_info *umem) {
	xsk_umem__delete(umem->umem);
	free(umem->buffer);
	free(umem->available_frames.addrs);
	free(umem);
}

int submit_initial_rx_frames(struct xsk_umem_info *umem) {
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

int submit_initial_tx_frames(struct xsk_umem_info *umem) {
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

int load_bpf(const void *prgm, ssize_t prgm_size, struct xdp_program **prog_o) {
	char tmp_file[] = "/tmp/hrcbpfXXXXXX";
	int fd = mkstemp(tmp_file);
	if (fd < 0) {
		return -errno;
	}
	if (prgm_size != write(fd, prgm, prgm_size)) {
		debug_printf("Could not write bpf file");
		return -EXIT_FAILURE;
	}

	struct xdp_program *prog = xdp_program__open_file(tmp_file, "xdp.frags", NULL);
	int err = libxdp_get_error(prog);
	char errmsg[1024];
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		debug_printf("aaa prog %s", errmsg);
		fprintf(stderr, "Error loading XDP program: %s\n", errmsg);
		return 1;
	}

	int unlink_ret = unlink(tmp_file);
	if (0 != unlink_ret) {
		fprintf(stderr, "Could not remove temporary file, error: %d",
				unlink_ret);
	}
	*prog_o = prog;
	return 0;
}

int xsk_map__add_xsk(xskmap map, int index,
					 struct xsk_socket_info *xsk) {
	int xsk_fd = xsk_socket__fd(xsk->xsk);
	if (xsk_fd < 0) {
		return 1;
	}
	int ret = bpf_map_update_elem(map, &index, &xsk_fd, 0);
	if (ret == -1) {
		return 1;
	}
	return 0;
}

/*
 * Load a BPF program redirecting IP traffic to the XSK.
 */
int load_xsk_redirect_userspace(struct hercules_server *server,
								struct worker_args *args[], int num_threads) {
	debug_printf("Loading XDP program for redirection");
	for (int i = 0; i < server->num_ifaces; i++) {
		int err;
		char errmsg[1024];
		struct xdp_program *prog;
		int ret = load_bpf(bpf_prgm_redirect_userspace,
						   bpf_prgm_redirect_userspace_size, &prog);
		if (ret) {
			return 1;
		}

		// Check if there's already xdp programs on the interface.
		// If possible, the program is added to the list of loaded programs.
		// If our redirect program is already present (eg. because we crashed and thus
		// didn't remove it), we try to replace it.
		struct xdp_multiprog *multi =
			xdp_multiprog__get_from_ifindex(server->ifaces[i].ifid);
		if (xdp_multiprog__is_legacy(multi)) {
			// In this case we cannot add ours and we don't know if it's safe to remove
			// the other program
			fprintf(stderr,
					"Error: A legacy XDP program is already loaded on interface %s\n",
					server->ifaces[i].ifname);
			return 1;
		}
		for (struct xdp_program *ifprog = xdp_multiprog__next_prog(NULL, multi);
			 ifprog != NULL; ifprog = xdp_multiprog__next_prog(ifprog, multi)) {
			debug_printf("iface program: %s, prio %u", xdp_program__name(ifprog),
						 xdp_program__run_prio(ifprog));
			if (!strcmp(xdp_program__name(ifprog), "hercules_redirect_userspace")) {
				// If our redirect program is already loaded, we replace it
				// XXX Relies on nobody else naming a program
				// hercules_redirect_userspace, so multiple Hercules instances per
				// machine are not possible. That could be solved with priorities, for
				// example.
				fprintf(stderr,
						">>> Hercules XDP program already loaded on interface, "
						"replacing.\n");
				err = xdp_program__detach(ifprog, server->ifaces[i].ifid,
										  XDP_MODE_UNSPEC, 0);
				if (err) {
					libxdp_strerror(err, errmsg, sizeof(errmsg));
					fprintf(stderr,
							"Error detaching XDP program from interface %s: %s\n",
							server->ifaces[i].ifname, errmsg);
					return 1;
				}
				ifprog = xdp_multiprog__next_prog(NULL, multi);
			}
		}

		err = xdp_program__attach(prog, server->ifaces[i].ifid, XDP_MODE_UNSPEC, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Error attaching XDP program to interface %s: %s\n",
					server->ifaces[i].ifname, errmsg);
			return 1;
		}
		enum xdp_attach_mode mode =
			xdp_program__is_attached(prog, server->ifaces[i].ifid);
		if (!mode) {
			fprintf(stderr, "Program not attached?\n");
			return 1;
		}
		fprintf(stderr, "XDP program attached in mode: %d\n", mode);
		server->ifaces[i].xdp_prog = prog;

		debug_printf("program supports frags? %d", xdp_program__xdp_frags_support(prog));

		// XXX It should be possible to check whether multi-buffer (jumbo-frames) are
		// supported with the following code, but this always returns 0. However, it
		// also returns 0 for zero-copy support on machines that are known to support
		// zero-copy (eg. zapdos), so something is wrong. Same thing happens if you use
		// the xdp-loader utility (from xdp-tools, it uses the same approach) to query
		// for feature support.
		/* LIBBPF_OPTS(bpf_xdp_query_opts, opts); */
		/* err = bpf_xdp_query(server->ifaces[i].ifid, 0, &opts); */
		/* if (err) { */
		/* 	debug_printf("query err"); */
		/* 	return 1; */
		/* } */
		/* debug_printf("opts %#llx, zc frags %#x", opts.feature_flags, opts.xdp_zc_max_segs); */


		// push XSKs
		int xsks_map_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), "xsks_map");
		if (xsks_map_fd < 0) {
			return 1;
		}
		for (int s = 0; s < num_threads; s++) {
			int ret =
				xsk_map__add_xsk(xsks_map_fd, s, args[s]->xsks[i]);
			if (ret) {
				return 1;
			}
		}

		// push XSKs meta
		int zero = 0;
		int num_xsks_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), "num_xsks");
		if (num_xsks_fd < 0) {
			return 1;
		}
		ret = bpf_map_update_elem(num_xsks_fd, &zero, &num_threads, 0);
		if (ret == -1) {
			return 1;
		}

		// push local address
		int local_addr_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), "local_addr");
		if (local_addr_fd < 0) {
			return 1;
		}
		ret = bpf_map_update_elem(local_addr_fd, &zero,
								  &server->config.local_addr, 0);
		if (ret == -1) {
			return 1;
		}
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
		if (umem == NULL) {
			debug_printf("Error in umem setup");
			return -1;
		}
		debug_printf("Configured umem");

		server->ifaces[i].xsks =
			calloc(server->config.n_threads, sizeof(*server->ifaces[i].xsks));
		if (server->ifaces[i].xsks == NULL) {
			return ENOMEM;
		}
		server->ifaces[i].umem = umem;
		ret = submit_initial_tx_frames(umem);
		if (ret) {
			return -ret;
		}
		ret = submit_initial_rx_frames(umem);
		if (ret) {
			return -ret;
		}
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
		for (int t = 0; t < server->config.n_threads; t++) {
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

			cfg.bind_flags |= XDP_USE_SG;
			ret = xsk_socket__create_shared(&xsk->xsk, server->ifaces[i].ifname,
											server->config.queue, umem->umem, &xsk->rx,
											&xsk->tx, &umem->fq, &umem->cq, &cfg);
			if (ret) {
				fprintf(stderr, "Error creating XDP socket in multibuffer mode\n");
				cfg.bind_flags = server->config.xdp_mode;
				ret = xsk_socket__create_shared(&xsk->xsk, server->ifaces[i].ifname,
												server->config.queue, umem->umem, &xsk->rx,
												&xsk->tx, &umem->fq, &umem->cq, &cfg);
				if (ret) {
					fprintf(stderr, "Error creating XDP socket\n");
					return -ret;
				}
			}
			/* ret = bpf_get_link_xdp_id(server->ifaces[i].ifid, */
			/* 						  &server->ifaces[i].prog_id, */
			/* 						  server->config.xdp_flags); */
			/* if (ret) { */
			/* 	return -ret; */
			/* } */
			server->ifaces[i].xsks[t] = xsk;
		}
		server->ifaces[i].num_sockets = server->config.n_threads;
	}
	for (int t = 0; t < server->config.n_threads; t++) {
		server->worker_args[t] = calloc(
			1, sizeof(**server->worker_args) +
				   server->num_ifaces * sizeof(*server->worker_args[t]->xsks));
		if (server->worker_args[t] == NULL) {
			return ENOMEM;
		}
		server->worker_args[t]->server = server;
		server->worker_args[t]->id = t + 1;
		for (int i = 0; i < server->num_ifaces; i++) {
			server->worker_args[t]->xsks[i] = server->ifaces[i].xsks[t];
		}
	}

	int ret = load_xsk_redirect_userspace(server, server->worker_args,
										  server->config.n_threads);
	if (ret) {
		fprintf(stderr, "Error loading XDP redirect, is another program loaded?\n");
		return ret;
	}

	if (server->config.configure_queues) {
		int ret = configure_rx_queues(server);
		if (ret != 0) {
			return ret;
		}
	}

	debug_printf("XSK stuff complete");
	return 0;
}

void xdp_teardown(struct hercules_server *server) {
	for (int i = 0; i < server->num_ifaces; i++) {
		for (int j = 0; j < server->config.n_threads; j++) {
			close_xsk(server->ifaces[i].xsks[j]);
		}
		destroy_umem(server->ifaces[i].umem);
	}
	remove_xdp_program(server);
	unconfigure_rx_queues(server);
}
