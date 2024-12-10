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

#ifndef HERCULES_ERRORS_H
#define HERCULES_ERRORS_H

// Some states are used only by the TX/RX side and are marked accordingly
enum session_state {
	SESSION_STATE_NONE,
	SESSION_STATE_PENDING,	//< (TX) Need to send HS and repeat until TO,
							// waiting for a reflected HS packet
	SESSION_STATE_NEW,	//< (RX) Received a HS packet, need to send HS reply and
						// CTS
	SESSION_STATE_WAIT_CTS,		 //< (TX) Waiting for CTS
	SESSION_STATE_INDEX_READY,	 //< (RX) Index transfer complete, map files and
								 // send CTS
	SESSION_STATE_RUNNING_DATA,	 //< Data transfer in progress
	SESSION_STATE_RUNNING_IDX,	 //< Directory index transfer in progress
	SESSION_STATE_DONE,			 //< Transfer done (or cancelled with error)
};

enum session_error {
	SESSION_ERROR_NONE,		// Error not set yet
	SESSION_ERROR_OK,		//< No error, transfer completed successfully
	SESSION_ERROR_TIMEOUT,	//< Session timed out
	SESSION_ERROR_STALE,	//< Packets are being received, but none are new
	SESSION_ERROR_PCC,		//< Something wrong with PCC
	SESSION_ERROR_SEQNO_OVERFLOW,
	SESSION_ERROR_NO_PATHS,	   //< Monitor returned no paths to destination
	SESSION_ERROR_CANCELLED,   //< Transfer cancelled by monitor
	SESSION_ERROR_BAD_MTU,	   //< Invalid MTU supplied by the monitor
	SESSION_ERROR_MAP_FAILED,  //< Could not mmap file
	SESSION_ERROR_TOO_LARGE,   //< File or index size too large
	SESSION_ERROR_INIT,		   //< Could not initialise session
};

static inline int hercules_err_is_ok(enum session_error err) {
	return err == SESSION_ERROR_OK;
}

static inline const char *hercules_strerror(enum session_error err) {
	switch (err) {
		case SESSION_ERROR_NONE:
			return "Error not set";
		case SESSION_ERROR_OK:
			return "Transfer successful";
		case SESSION_ERROR_TIMEOUT:
			return "Session timed out";
		case SESSION_ERROR_STALE:
			return "Session stalled";
		case SESSION_ERROR_PCC:
			return "PCC error";
		case SESSION_ERROR_SEQNO_OVERFLOW:
			return "PCC sequence number overflow";
		case SESSION_ERROR_NO_PATHS:
			return "No paths to destination";
		case SESSION_ERROR_CANCELLED:
			return "Transfer cancelled";
		case SESSION_ERROR_BAD_MTU:
			return "Bad MTU";
		case SESSION_ERROR_MAP_FAILED:
			return "Mapping file failed";
		case SESSION_ERROR_TOO_LARGE:
			return "File or directory listing too large";
		case SESSION_ERROR_INIT:
			return "Could not initialise session";
		default:
			return "Unknown error";
	}
}

#endif	// HERCULES_ERRORS_H
