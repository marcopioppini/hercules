HERCULES(7) - Miscellaneous Information Manual

# NAME

**Hercules** - SCION-native fast bulk data transfers

# DESCRIPTION

**Hercules**
is a high-speed SCION-native bulk data transfer application.
Hercules achieves high transfer rates by combining the Linux kernel AF\_XDP
express data path and PCC congestion control with a custom data transfer
protocol.
Hercules can take advantage of SCION's native multipath capabilities to transfer
data using multiple network paths simultaneously.
Hercules supports transferring entire directories in one go.

The Hercules server is intended to run on dedicated machines.
A Hercules server installation consists of two components, i.e.,
two separate processes that communicate via a Unix socket.

*	The monitor is responsible for handling SCION paths and exposes a HTTP API which
	clients can use to submit new transfers, check the status of ongoing transfers,
	or cancel them.

*	The server carries out the actual file transfers.

The monitor and server processes must be started and stopped together, you
should not restart one without also restarting the other.
The provided systemd service files ensure this, if you use a different method
to run Hercules you must ensure this yourself.

Clients interact with Hercules via its HTTP API.
The easiest way for users to transfer files is using the provided
hcp(1)
command line tool.

# EXAMPLES

The following example scenario illustrates how Hercules is intended to be used
and how the various components interact.
Assume we want to use Hercules to transfer data between two locations,
from
*A*
to
*B*.
We will need to set up an instance of Hercules, ideally on a dedicated machine,
at each location.
Both machines need a working SCION endhost stack.
Instructions on setting up a SCION endhost can be found at
[https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html](https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html).
Assume the SCION addresses of the two machines are
'`64-2:0:9,10.1.1.1`'
and
'`64-2:0:c,10.2.2.2`',
respectively, and that the corresponding network interfaces on both machines are
called
'`eth0`'.
We will use SCION/UDP port 10000 for Hercules on both hosts.
We will use the default TCP port 8000 for the HTTP API.
With Hercules installed on both machines, we set the following configuration
options on the two machines:

On the machine at
*A*:

	ListenAddress = "64-2:0:9,10.1.1.1:10000"
	Interfaces = [ "eth0" ]

On the machine at
*B*:

	ListenAddress = "64-2:0:c,10.2.2.2:10000"
	Interfaces = [ "eth0" ]

We can now start the Hercules server on both machines.
With the provided systemd files, this is done with the following command:

	# systemctl start hercules-server

Note that this will start both the Hercules server and monitor processes.

Now, we can use
hcp(1)
to copy the file
*/tmp/hercules.in*
from
*A*
to
*B*
by running the following command on
*A*:

	$ hcp localhost:8000 /tmp/hercules.in 64-2:0:c,10.2.2.2:10000 /tmp/hercules.out

# SEE ALSO

hcp(1),
hercules-monitor(1),
hercules-server(1),
hercules.conf(5),

Further information about Hercules is available on
[https://github.com/netsec-ethz/hercules](https://github.com/netsec-ethz/hercules).
For more information about SCION, please see
[https://scion-architecture.net](https://scion-architecture.net).

# AUTHORS

Network Security Group, ETH Z"urich

Void Linux - October 30, 2024
