#include "monitor.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "hercules.h"
#include "utils.h"

bool monitor_get_reply_path(int sockfd, const char *rx_sample_buf,
							int rx_sample_len, int etherlen,
							struct hercules_path *path) {
	struct sockaddr_un monitor;
	monitor.sun_family = AF_UNIX;
	strcpy(monitor.sun_path, "/var/herculesmon.sock");

	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_GET_REPLY_PATH;
	msg.payload.reply_path.etherlen = etherlen;
	msg.payload.reply_path.sample_len = rx_sample_len;
	memcpy(msg.payload.reply_path.sample, rx_sample_buf, rx_sample_len);
	sendto(sockfd, &msg, sizeof(msg), 0, &monitor,
		   sizeof(monitor));  // TODO return val

	struct hercules_sockmsg_A reply;
	int n = recv(sockfd, &reply, sizeof(reply), 0);
	debug_printf("Read %d bytes", n);
	if (n <= 0) {
		return false;
	}
	memcpy(&path->header, reply.payload.reply_path.path.header,
		   reply.payload.reply_path.path.headerlen);
	path->headerlen = reply.payload.reply_path.path.headerlen;
	path->header.checksum = reply.payload.reply_path.path.chksum;
	path->enabled = true;
	path->payloadlen = etherlen - path->headerlen;
	path->framelen = etherlen;
	path->ifid = reply.payload.reply_path.path.ifid;
	return true;
}

// The payload length is fixed when first fetching the job, we pass it in here
// to compute the paths payload and frame lengths.
bool monitor_get_paths(int sockfd, int job_id, int payloadlen, int *n_paths,
					   struct hercules_path **paths) {
	struct sockaddr_un monitor;
	monitor.sun_family = AF_UNIX;
	strcpy(monitor.sun_path, "/var/herculesmon.sock");

	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_GET_PATHS;
	msg.payload.paths.job_id = job_id;
	sendto(sockfd, &msg, sizeof(msg), 0, &monitor, sizeof(monitor));

	struct hercules_sockmsg_A reply;
	int n = recv(sockfd, &reply, sizeof(reply), 0);
	debug_printf("receive %d bytes", n);

	int received_paths = reply.payload.paths.n_paths;
	struct hercules_path *p =
		calloc(received_paths, sizeof(struct hercules_path));

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

bool monitor_get_new_job(int sockfd, char *name, u16 *job_id,
						 struct hercules_app_addr *dest, u16 *payloadlen) {
	struct sockaddr_un monitor;
	monitor.sun_family = AF_UNIX;
	strcpy(monitor.sun_path, "/var/herculesmon.sock");

	struct hercules_sockmsg_Q msg = {.msgtype = SOCKMSG_TYPE_GET_NEW_JOB};
	sendto(sockfd, &msg, sizeof(msg), 0, &monitor, sizeof(monitor));

	struct hercules_sockmsg_A reply;
	int n = recv(sockfd, &reply, sizeof(reply), 0);
	if (!reply.payload.newjob.has_job) {
		return false;
	}
	// XXX name needs to be allocated large enough by caller
	strncpy(name, reply.payload.newjob.filename,
			reply.payload.newjob.filename_len);
	*job_id = reply.payload.newjob.job_id;
	debug_printf("received job id %d", reply.payload.newjob.job_id);
	*payloadlen = reply.payload.newjob.payloadlen;
	return true;
}

bool monitor_update_job(int sockfd, int job_id, enum session_state state,
						enum session_error err, u64 seconds_elapsed,
						u64 bytes_acked) {
	struct sockaddr_un monitor;
	monitor.sun_family = AF_UNIX;
	strcpy(monitor.sun_path, "/var/herculesmon.sock");

	struct hercules_sockmsg_Q msg;
	msg.msgtype = SOCKMSG_TYPE_UPDATE_JOB;
	msg.payload.job_update.job_id = job_id;
	msg.payload.job_update.status = state;
	msg.payload.job_update.error = err;
	msg.payload.job_update.seconds_elapsed = seconds_elapsed;
	msg.payload.job_update.bytes_acked = bytes_acked;
	sendto(sockfd, &msg, sizeof(msg), 0, &monitor, sizeof(monitor));

	struct hercules_sockmsg_A reply;
	int n = recv(sockfd, &reply, sizeof(reply), 0);
	if (!reply.payload.job_update.ok) {
		return false;
	}
	return true;
}

#define HERCULES_DAEMON_SOCKET_PATH "/var/hercules.sock"
int monitor_bind_daemon_socket() {
	int usock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (usock <= 0) {
		return 0;
	}
	struct sockaddr_un name;
	name.sun_family = AF_UNIX;
	strcpy(name.sun_path, HERCULES_DAEMON_SOCKET_PATH);
	unlink(HERCULES_DAEMON_SOCKET_PATH);
	int ret = bind(usock, &name, sizeof(name));
	if (ret) {
		return 0;
	}
	return usock;
}
