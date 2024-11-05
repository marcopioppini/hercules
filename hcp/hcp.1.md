HCP(1) - General Commands Manual

# NAME

**hcp** - Copy files using Hercules

# SYNOPSIS

**hcp**
\[OPTIONS]
*SOURCE-API*
*SOURCE-PATH*
*DEST-ADDR*
*DEST-PATH*

# DESCRIPTION

**hcp**
is an easy-to-use tool to copy files using the Hercules file transfer system.
It interacts with the Hercules server's API on behalf of the user.
It instructs the source Hercules server, whose API is exposed on
*SOURCE-API*
to transfer the file (or directory)
*SOURCE-PATH*
to the destination Hercules server whose SCION/UDP address is
*DEST-ADDR*
and store it under
*DEST-PATH*.
Once a transfer is submitted,
**hcp**
will periodically poll the Hercules server for information about the transfer's
progress and show this information to the user.

Note that the paths must be supplied from the point of view of the source and
destination Hercules servers, respectively.
If
**hcp**
is run from a different machine than the source Hercules server, the source file
must first be made available to the Hercules server.
Doing so is outside the scope of this tool,
but this may be achieved by means of a network mount, or by attaching storage
media containing the file to the machine running the Hercules server.

The options are as follows:

**-i** *poll\_freq*

> How frequently to poll the server for transfer status updates.
> The argument is a go duration string.
> The default polling frequency is
> *1s*,
> that is, poll every second.

**-l** *payload\_length*

> Manually set the payload size to use for this transfer.
> This is useful if Hercules' automatic selection does not work, for example,
> if a path advertises a MTU larger than what it really supports.
> Note that the packet length includes the headers in addition to the payload,
> so the payload length must set to a value smaller than the MTU.

**-n**

> Do not ask the server for the file's total size before submitting the transfer.
> With this option set, the progress bar and time estimates are not shown.

**-version**

> Print version information and exit.

# EXAMPLES

If you are running this tool on the same machine as the source
Hercules server and want to transfer the file
*/tmp/hercules.in*
to
*/tmp/hercules.out*,
with the destination Hercules server listening on
*64-2:0:9,192.168.4.2:10000*,
run the following command:

	$ hcp localhost:8000 /tmp/hercules.in 64-2:0:9,192.168.4.2:10000 /tmp/hercules.out

If your are running the Hercules server on a dedicated machine, with its API
accessible on
*10.0.0.1:8000*,
you have copied the file you want to transfer,
*hercules.in*,
to a network share mounted at
*/mnt/data*
on the Hercules server, and want to submit run hcp from a different host:

	$ hcp 10.0.0.1:8000 /mnt/data/hercules.in 64-2:0:9,192.168.4.2:10000 /tmp/hercules.out

# SEE ALSO

hercules-monitor(1),
hercules-server(1),
hercules.conf(5),
hercules(7)

Further information about Hercules is available on
[https://github.com/netsec-ethz/hercules](https://github.com/netsec-ethz/hercules).
For more information about SCION, please see
[https://scion-architecture.net](https://scion-architecture.net).

# AUTHORS

Network Security Group, ETH Z&#252;rich

Void Linux - October 29, 2024
