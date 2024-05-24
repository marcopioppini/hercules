#include "monitor.h"
#include "hercules.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

bool monitor_get_reply_path(int sockfd, char *rx_sample_buf, int rx_sample_len, int etherlen,
                            struct hercules_path *path) {
  struct sockaddr_un monitor;
  monitor.sun_family = AF_UNIX;
  strcpy(monitor.sun_path, "/var/herculesmon.sock");

  struct hercules_sockmsg_Q *msg;
  size_t msg_len = sizeof(*msg) + rx_sample_len;
  msg = calloc(1, msg_len);
  assert(msg);

  msg->msgtype = SOCKMSG_TYPE_GET_REPLY_PATH;
  msg->payload.reply_path.etherlen = etherlen;
  msg->payload.reply_path.sample_len = rx_sample_len;
  memcpy(msg->payload.reply_path.sample, rx_sample_buf, rx_sample_len);
  debug_printf("sending %ld bytes", msg_len);
  sendto(sockfd, msg, msg_len, 0, &monitor, sizeof(monitor)); // TODO return val
  free(msg);

  char buf[2000];
  memset(&buf, 0, 2000);
  int n = recv(sockfd, &buf, sizeof(buf), 0);
  debug_printf("Read %d bytes", n);
  if (n <= 0) {
    return false;
  }
  struct hercules_sockmsg_A *reply = buf;
  path->headerlen = reply->payload.reply_path.headerlen;
  memcpy(&path->header.header, reply->payload.reply_path.header,
         path->headerlen);
  path->header.checksum = reply->payload.reply_path.chksum;

  path->enabled = true;
  path->replaced = false;
  path->payloadlen = 1200 - path->headerlen;
  path->framelen = 1200;
  path->ifid = 3;
  return true;
}

bool monitor_get_paths(int sockfd, int job_id, int *n_paths,
                       struct hercules_path **paths) {
  struct hercules_path *path = calloc(1, sizeof(*path));
  assert(path);

  struct sockaddr_un monitor;
  monitor.sun_family = AF_UNIX;
  strcpy(monitor.sun_path, "/var/herculesmon.sock");
  struct hercules_sockmsg_Q msg = {.msgtype = SOCKMSG_TYPE_GET_PATHS};
  int len = sizeof(msg);
  debug_printf("sending %d bytes", len);
  sendto(sockfd, &msg, len, 0, &monitor, sizeof(monitor));
  char recvbuf[2000];
  memset(&recvbuf, 0, 2000);
  int n = recv(sockfd, &recvbuf, sizeof(recvbuf), 0);
  debug_printf("receive %d bytes", n);
  struct sockmsg_reply_path_A *reply = recvbuf + 2;
  path->headerlen = reply->headerlen;
  memcpy(path->header.header, reply->header, reply->headerlen);
  path->header.checksum = reply->chksum;

  path->enabled = true;
  path->replaced = false;
  path->payloadlen = 1200 - path->headerlen;
  path->framelen = 1200;
  path->ifid = 3;

  *n_paths = 1;
  *paths = path;
  return true;
}

bool monitor_get_new_job(int sockfd, char *name, u16 *job_id, struct hercules_app_addr *dest) {
  struct sockaddr_un monitor;
  monitor.sun_family = AF_UNIX;
  strcpy(monitor.sun_path, "/var/herculesmon.sock");
  struct hercules_sockmsg_Q msg = {.msgtype = SOCKMSG_TYPE_GET_NEW_JOB};
  int len = sizeof(msg);
  debug_printf("sending %d bytes", len);
  sendto(sockfd, &msg, len, 0, &monitor, sizeof(monitor));
  char recvbuf[2000];
  memset(&recvbuf, 0, 2000);
  int n = recv(sockfd, &recvbuf, sizeof(recvbuf), 0);
  debug_printf("receive %d bytes", n);
  struct sockmsg_new_job_A *reply = recvbuf;
  if (!reply->has_job){
    return false;
  }
  strncpy(name, reply->filename, reply->filename_len);
  *job_id = reply->job_id;
  return true;
}

#define HERCULES_DAEMON_SOCKET_PATH "/var/hercules.sock"
// Bind the socket for the daemon. The file is deleted if already present.
// Returns the file descriptor if successful, 0 otherwise.
int monitor_bind_daemon_socket(){
  int usock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (usock <= 0){
    return 0;
  }
  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, HERCULES_DAEMON_SOCKET_PATH);
  unlink(HERCULES_DAEMON_SOCKET_PATH);
  int ret = bind(usock, &name, sizeof(name));
  if (ret){
    return 0;
  }
  return usock;
}
