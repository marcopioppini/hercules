#ifndef HERCULES_MONITOR_H_
#define HERCULES_MONITOR_H_
#include "hercules.h"
#include <stdbool.h>
#include <stdint.h>

// Get a reply path from the monitor. The reversed path will be written to
// *path. Returns false in case of error.
bool monitor_get_reply_path(int sockfd, char *rx_sample_buf, int rx_sample_len,
                            struct hercules_path *path);

// Get SCION paths from the monitor. The caller is responsible for freeing
// **paths.
bool monitor_get_paths(int sockfd, int job_id, int *n_paths,
                       struct hercules_path **paths);

// Check if the monitor has a new job available
// TODO
bool monitor_get_new_job(int sockfd, char *name);

// Inform the monitor about a transfer's (new) status
// TODO
bool monitor_update_job(int sockfd, int job_id);

int monitor_bind_daemon_socket();

// Messages used for communication between the Hercules daemon and monitor
// via unix socket. Queries are sent by the daemon, Replies by the monitor.
#pragma pack(push)
#pragma pack(1)

// Ask the monitor for a reply path by sending it a received header.
// The monitor will return the appropriate header, along with its partial
// checksum
#define SOCKMSG_TYPE_GET_REPLY_PATH (1)
struct sockmsg_reply_path_Q {
  uint16_t sample_len;
  uint8_t sample[];
};
struct sockmsg_reply_path_A {
  uint16_t chksum;
  uint32_t headerlen;
  uint8_t header[];
};

// Ask the monitor for new transfer jobs.
// The answer contains at most one new job, if one was queued at the monitor.
#define SOCKMSG_TYPE_GET_NEW_JOB (2)
struct sockmsg_new_job_Q {};
struct sockmsg_new_job_A {
  uint8_t has_job; // The other fields are only valid if this is set to 1
  uint16_t job_id;
  uint16_t filename_len;
  uint8_t filename[];
};

// Get paths to use for a given job ID
#define SOCKMSG_TYPE_GET_PATHS (3)
struct sockmsg_paths_Q {
  uint16_t job_id;
};
struct sockmsg_paths_A {
  uint16_t n_paths;
  uint8_t paths[]; // This should be a concatenation of n_paths many paths, each
                   // laid out as struct sockmsg_reply_path_A above.
};

// Inform the monitor about a job's status
#define SOCKMSG_TYPE_UPDATE_JOB (4)
struct sockmsg_update_job_Q {
  uint16_t job_id;
  uint32_t status; // One of enum session_state
  uint32_t error;  // One of enum session_error
};
struct sockmsg_update_job_A {};

struct hercules_sockmsg_Q {
  uint16_t msgtype;
  union {
    struct sockmsg_reply_path_Q reply_path;
    struct sockmsg_paths_Q paths;
    struct sockmsg_new_job_Q newjob;
    struct sockmsg_update_job_Q job_update;
  } payload;
};

struct hercules_sockmsg_A {
  union {
    struct sockmsg_reply_path_A reply_path;
    struct sockmsg_paths_A paths;
    struct sockmsg_new_job_A newjob;
    struct sockmsg_update_job_A job_update;
  } payload;
};

#pragma pack(pop)

#endif // HERCULES_MONITOR_H_
