#include "monitor.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "hercules.h"
#include "utils.h"

static bool monitor_send_recv(int sockfd, struct hercules_sockmsg_Q *in,
							  struct hercules_sockmsg_A *out) {
	int ret = send(sockfd, in, sizeof(*in), 0);
	if (ret != sizeof(*in)) {
		debug_printf("Error sending to monitor?");
		return false;
	}
	ret = recv(sockfd, out, sizeof(*out), 0);
	if (ret <= 0) {
		debug_printf("Error reading from monitor?");
		return false;
	}
	return true;
}

bool monitor_get_reply_path(int sockfd, const char *rx_sample_buf,
							int rx_sample_len, int etherlen,
							_Atomic struct hercules_path *path) {
	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_GET_REPLY_PATH;
	msg.payload.reply_path.etherlen = etherlen;
	msg.payload.reply_path.sample_len = rx_sample_len;
	memcpy(msg.payload.reply_path.sample, rx_sample_buf, rx_sample_len);

	struct hercules_sockmsg_A reply;
	int ret = monitor_send_recv(sockfd, &msg, &reply);
	if (!ret) {
		return false;
	}
	if (!reply.payload.reply_path.reply_path_ok){
		return false;
	}

	struct hercules_path new_reply_path = {
		.headerlen = reply.payload.reply_path.path.headerlen,
		.header.checksum = reply.payload.reply_path.path.chksum,
		.enabled = true,
		.payloadlen = etherlen - reply.payload.reply_path.path.headerlen,
		.framelen = etherlen,
		.ifid = reply.payload.reply_path.path.ifid,
	};
	memcpy(&new_reply_path.header, reply.payload.reply_path.path.header,
		   reply.payload.reply_path.path.headerlen);

	atomic_store(path, new_reply_path);
	return true;
}

// The payload length is fixed when first fetching the job, we pass it in here
// to compute the paths payload and frame lengths.
bool monitor_get_paths(int sockfd, int job_id, int payloadlen, int *n_paths,
					   struct hercules_path **paths) {
	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_GET_PATHS;
	msg.payload.paths.job_id = job_id;

	struct hercules_sockmsg_A reply;
	int ret = monitor_send_recv(sockfd, &msg, &reply);
	if (!ret) {
		return false;
	}

	int received_paths = reply.payload.paths.n_paths;
	assert(received_paths <= SOCKMSG_MAX_PATHS);
	struct hercules_path *p =
		calloc(received_paths, sizeof(struct hercules_path));
	if (p == NULL) {
		return false;
	}

	for (int i = 0; i < received_paths; i++) {
		p[i].headerlen = reply.payload.paths.paths[i].headerlen;
		memcpy(&p[i].header, reply.payload.paths.paths[i].header,
			   p[i].headerlen);
		p[i].header.checksum = reply.payload.paths.paths[i].chksum;
		p[i].enabled = true;
		p[i].payloadlen = payloadlen;
		p[i].framelen = p[i].headerlen + payloadlen;
		p[i].ifid = reply.payload.paths.paths[i].ifid;
	}

	*n_paths = received_paths;
	*paths = p;
	return true;
}

bool monitor_get_new_job(int sockfd, char **name, char **destname, u16 *job_id,
						 struct hercules_app_addr *dest, u16 *payloadlen) {
	struct hercules_sockmsg_Q msg = {.msgtype = SOCKMSG_TYPE_GET_NEW_JOB};

	struct hercules_sockmsg_A reply;
	int ret = monitor_send_recv(sockfd, &msg, &reply);
	if (!ret) {
		return false;
	}

	if (!reply.payload.newjob.has_job) {
		return false;
	}
	assert(reply.payload.newjob.filename_len +
			   reply.payload.newjob.destname_len <=
		   SOCKMSG_MAX_PAYLOAD);

	*name = calloc(1, reply.payload.newjob.filename_len + 1);
	if (*name == NULL) {
		return false;
	}
	*destname = calloc(1, reply.payload.newjob.destname_len + 1);
	if (*destname == NULL) {
		free(*name);
		return false;
	}

	strncpy(*name, (char *)reply.payload.newjob.names,
			reply.payload.newjob.filename_len);
	strncpy(
		*destname,
		(char *)reply.payload.newjob.names + reply.payload.newjob.filename_len,
		reply.payload.newjob.destname_len);
	debug_printf("received job id %d", reply.payload.newjob.job_id);
	*job_id = reply.payload.newjob.job_id;
	*payloadlen = reply.payload.newjob.payloadlen;
	dest->ia = reply.payload.newjob.dest_ia;
	dest->ip = reply.payload.newjob.dest_ip;
	dest->port = reply.payload.newjob.dest_port;
	return true;
}

bool monitor_update_job(int sockfd, int job_id, enum session_state state,
						enum session_error err, u64 seconds_elapsed,
						u64 bytes_acked) {
	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_UPDATE_JOB;
	msg.payload.job_update.job_id = job_id;
	msg.payload.job_update.status = state;
	msg.payload.job_update.error = err;
	msg.payload.job_update.seconds_elapsed = seconds_elapsed;
	msg.payload.job_update.bytes_acked = bytes_acked;

	struct hercules_sockmsg_A reply;
	int ret = monitor_send_recv(sockfd, &msg, &reply);
	if (!ret) {
		return false;
	}

	if (!reply.payload.job_update.ok) {
		return false;
	}
	return true;
}

int monitor_bind_daemon_socket(char *server, char *monitor) {
	int usock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (usock <= 0) {
		return 0;
	}
	struct sockaddr_un name;
	name.sun_family = AF_UNIX;
	// Unix socket paths limited to 107 chars
	strncpy(name.sun_path, server, sizeof(name.sun_path)-1);
	unlink(server);
	int ret = bind(usock, (struct sockaddr *)&name, sizeof(name));
	if (ret) {
		return 0;
	}

	struct sockaddr_un monitor_sock;
	monitor_sock.sun_family = AF_UNIX;
	strncpy(monitor_sock.sun_path, monitor, 107);
	ret =
		connect(usock, (struct sockaddr *)&monitor_sock, sizeof(monitor_sock));
	if (ret) {
		return 0;
	}
	return usock;
}
