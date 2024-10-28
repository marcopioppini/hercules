# Hercules HTTP API

The Monitor's API supports the following operations via HTTP GET requests.

### `/submit`: Submitting a new transfer
Parameters:
- `file`: Path to source file, from the server's point of view
- `dest`: SCION address of the destination Hercules server
- `destfile`: Destination file path
- `payloadlen`: (Optional) override automatic MTU selection and use the specified payload length instead.

Example: `localhost:8000/submit?file=infile&destfile=outfile&dest=64-2:0:c,148.187.128.136:8000`

Returns: `OK id`, where `id` is an integer identifying the submitted job on success, an HTTP error code otherwise.

### `/status`: Check a transfer's status
Parameters:
- `id`: An id previously returned by `/submit`.

Returns: `OK status state error time_elapsed bytes_acked` on success, an HTTP error code otherwise.
- `status` is the monitor's internal transfer status and one of `TransferStatus`, as defined in the go code.
- `state` is an integer corresponding to the transfers current status (one of `session_state`, as defined in `errors.h`)
- `error` is an integer corresponding to the transfers error state (one of `session_error`, as defined in `errors.h`)
- `time_elapsed` is an integer representing the number of seconds elapsed since the server started this transfer.
- `bytes_acked` is the number of bytes acknowledged by the receiver.

### `/cancel`: Cancel a transfer
Parameters:
- `id`: An id previously returned by `/submit`.

Returns: `OK`on success, an HTTP error code otherwise.

### `/server`: Returns the server's SCION address
This functionality is provided for integration with FTS.

Parameters: None

Returns: `OK addr`, where `addr` is the server's SCION address.

### `/stat`: Retrieve stat information on a file
This is provided for compatibility with FTS, but also (optionally) used by hcp.

Parameters:
- `file`: Path to file (or directory)

Returns: `OK exists size`, where `exists` is 1 if the file exists, 0 otherwise; `size` is the file's size in bytes. If `file` is a directory, `size` is the size of all regular files contained in the directory and its subdirectories.
