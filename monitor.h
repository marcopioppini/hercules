// Copyright 2024 ETH Zurich
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

#ifndef HERCULES_MONITOR_H_
#define HERCULES_MONITOR_H_
#include <stdbool.h>
#include <stdint.h>

#include "hercules.h"
#include "utils.h"

// Get a reply path from the monitor. Supply a received packet, the monitor will
// parse it and reverse the SCION path. The header with the reversed path will
// be written to *path. Returns false in case of error.
bool monitor_get_reply_path(int sockfd, const char *rx_sample_buf,
							int rx_sample_len, int etherlen,
							_Atomic struct hercules_path *path);

// Get SCION paths from the monitor for a given job ID. The caller is
// responsible for freeing **paths.
// Returns false on error.
bool monitor_get_paths(int sockfd, u64 job_id, int payloadlen, int *n_paths,
					   struct hercules_path **paths);

// Check if the monitor has a new job available.
// If so the function returns true and the job's details are filled into the
// arguments.
// Returns false if no new job available OR on error.
// The caller is responsible for freeing **name and **destname if the return
// value was true.
bool monitor_get_new_job(int sockfd, char **name, char **destname, u64 *job_id,
						 struct hercules_app_addr *dest, u16 *payloadlen);

// Inform the monitor about a transfer's status.
// Returns false if the job was cancelled by the monitor or on error.
bool monitor_update_job(int sockfd, u64 job_id, enum session_state state,
						enum session_error err, u64 seconds_elapsed,
						u64 bytes_acked);

// Bind and connect the socket for communication with the monitor. The file is
// deleted if already present. Returns the file descriptor if successful, 0
// otherwise.
int monitor_bind_daemon_socket(char *server, char *monitor);

#define HERCULES_DEFAULT_MONITOR_SOCKET "/var/run/herculesmon.sock"
#define HERCULES_DEFAULT_DAEMON_SOCKET "/var/run/hercules.sock"

// Maximum size of variable-length fields in socket messages. Since we pass
// entire packets to the monitor to get reply paths, this must be at least as
// large as HERCULES_MAX_PKT_SIZE.
#define SOCKMSG_MAX_PAYLOAD 10000
_Static_assert(SOCKMSG_MAX_PAYLOAD >= HERCULES_MAX_PKTSIZE,
			   "Socket messages too small");

// Maximum number of paths transferred
#define SOCKMSG_MAX_PATHS 10

// The following messages are used for communication between the Hercules daemon
// and monitor via unix socket. Queries are sent by the daemon, Replies by the
// monitor. Structs suffixed _Q are queries, ones suffixed _A are answers.
#pragma pack(push)
#pragma pack(1)

// Ask the monitor for a reply path by sending it a received header.
// The monitor will return the appropriate header, along with its partial
// checksum
#define SOCKMSG_TYPE_GET_REPLY_PATH (1)
struct sockmsg_reply_path_Q {
	uint16_t sample_len;
	uint16_t etherlen;
	uint8_t sample[SOCKMSG_MAX_PAYLOAD];
};
struct sockmsg_serialized_path {
	uint16_t chksum;
	uint16_t ifid;
	uint32_t headerlen;
	uint8_t header[HERCULES_MAX_HEADERLEN];
};

struct sockmsg_reply_path_A {
	uint8_t reply_path_ok;
	struct sockmsg_serialized_path path;
};

// Ask the monitor for a new transfer job.
// The answer contains at most one new job, if one was queued at the monitor.
#define SOCKMSG_TYPE_GET_NEW_JOB (2)
struct sockmsg_new_job_Q {};
struct sockmsg_new_job_A {
	uint8_t has_job;  // The other fields are only valid if this is set to 1
	uint64_t job_id;
	uint64_t dest_ia;  //< Destination address in network byte order
	uint32_t dest_ip;
	uint16_t dest_port;
	uint16_t payloadlen;
	uint16_t filename_len;	// String length, excluding terminating 0-byte
	uint16_t destname_len;	// Same
	uint8_t names[SOCKMSG_MAX_PAYLOAD];	 // Concatenated filenames *without*
										 // terminating 0-byte
};

// Get paths to use for a given job ID
#define SOCKMSG_TYPE_GET_PATHS (3)
struct sockmsg_paths_Q {
	uint64_t job_id;
};
struct sockmsg_paths_A {
	uint16_t n_paths;
	struct sockmsg_serialized_path paths[SOCKMSG_MAX_PATHS];
};

// Inform the monitor about a job's status
#define SOCKMSG_TYPE_UPDATE_JOB (4)
struct sockmsg_update_job_Q {
	uint64_t job_id;
	uint32_t status;  // One of enum session_state
	uint32_t error;	  // One of enum session_error
	uint64_t seconds_elapsed;
	uint64_t bytes_acked;
};
struct sockmsg_update_job_A {
	uint16_t ok;
};

struct hercules_sockmsg_Q {
	uint16_t msgtype;
	uint16_t msgno;
	union {
		struct sockmsg_reply_path_Q reply_path;
		struct sockmsg_paths_Q paths;
		struct sockmsg_new_job_Q newjob;
		struct sockmsg_update_job_Q job_update;
	} payload;
};
// Used by go code
#define SOCKMSG_SIZE sizeof(struct hercules_sockmsg_Q)

struct hercules_sockmsg_A {
	uint16_t msgno;
	union {
		struct sockmsg_reply_path_A reply_path;
		struct sockmsg_paths_A paths;
		struct sockmsg_new_job_A newjob;
		struct sockmsg_update_job_A job_update;
	} payload;
};

#pragma pack(pop)

#endif	// HERCULES_MONITOR_H_
