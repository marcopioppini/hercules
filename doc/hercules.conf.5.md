HERCULES.CONF(5) - File Formats Manual

# NAME

**hercules.conf** - Hercules configuration file

# DESCRIPTION

**hercules.conf**
is the configuration file for the Hercules file transfer system.
This configuration file is used by
hercules-server(1)
and
hercules-monitor(1).
Its default location is
*/usr/local/etc/hercules.conf*.
The configuration file is in TOML format.

The following two options must be set, as they have no default values:

**ListenAddress**=*str*

> This specifies the SCION/UDP address Hercules will listen on
> for incoming transfers.

> Example: ListenAddress = "17-ffaa:1:fe2,192.168.10.141:8000"

**Interfaces**=\[*str*,]

> The network interface Hercules should use for data traffic.
> Hercules will load an XDP program on this interface.

> Example: Interfaces = \["eth0"]

It is
*strongly*
recommended to also set the
**DropUser**
and/or
**ChrootDir**
options, described below.
See
*CAVEATS*
for more information.

## GENERAL CONFIGURATION

The following general configuration options are available:

**DefaultNumPaths**=*int*

> Specify how many SCION path to use for data transfers.
> This is an upper limit, if fewer paths are available only those will be used.
> This value may be overridden on a per-destination basis, see
> *PER-DESTINATION OVERRIDES*.
> The default value is
> *1*.

> Example: DefaultNumPaths = 2

**MonitorSocket**=*str*

> Path to the monitor's Unix socket.
> The default value is
> */var/run/herculesmon.sock*.

**ServerSocket**=*str*

> Path to the server's Unix socket.
> The default value is
> */var/run/hercules.sock*.

**MonitorHTTP**=*str*

> The address and port on which to expose the Hercules HTTP API.
> This option may be set to the special string "disabled"
> to disable the HTTP API.
> The default value is
> *:8000*.

> Example: MonitorHTTP = "0.0.0.0:1818"

**DropUser**=*str*

> Name of a local system user.
> If specified, the server will drop its privileges to this user after startup.
> If unspecified, the server will run as root.
> Running the server as root is discouraged, as it presents a security risk.
> See
> *CAVEATS*
> for more information.

> Example: DropUser = "\_hercules"

**ChrootDir**=*str*

> If specified, the server process' root directory and working directory will be
> set to this path after startup.
> Note that it is possible to escape from a chroot under some circumstances;
> see
> chroot(2)
> for more information.
> When setting this option, note that the file paths supplied by users will be
> interpreted relative to this new directory.

> Example: DropUser = "/mnt/data/"

**EnablePCC**=*bool*

> Setting this option to
> *false*
> disables PCC congestion control and Hercules will send as fast as possible,
> up to its rate limit (see below).
> This may be useful for testing, but sending without congestion control across
> public networks is probably a bad idea.
> The default value is
> *true*.

**RateLimit**=*int*

> This option limits Hercules' sending rate.
> The limit is applied to each transfer indivudually.
> The value is in packets per second.
> The default value is
> *3'333'333*.

**NumThreads**=*int*

> Set the number of RX/TX worker threads to use.
> Setting this number to 2, for example, will start 2 RX worker threads
> and 2 TX workers.
> Depending on the bottleneck in your setup, increasing this number will
> improve performance.
> Hercules spawns other threads, too, so this is
> *not*
> the total number of threads used by Hercules.
> The default value is
> *1*.

**RxOnly**=*bool*

> Run the server in receive-only mode, do not start the TX threads.
> The default value is
> *false*.

**TxOnly**=*bool*

> Run the server in send-only mode, do not start the RX threads.
> The default value is
> *false*.

**XDPZeroCopy**=*bool*

> If your combination of NIC/drivers supports XDP in zero-copy mode,
> enabling it here will likely improve performance.
> The default value is
> *false*.

**XDPMultiBuffer**=*bool*

> If the system does not support XDP in multibuffer mode, this option can be used
> to disable it.
> As this functionality is required for jumbo frame support,
> disabling it limits the packet size to 3000B.
> The default value is
> *true*.

**Queue**=*int*

> Specify the NIC RX queue on which to receive packets.
> The default value is
> *0*.

**ConfigureQueues**=*bool*

> For Hercules to receive traffic, packets must be redirected to the queue
> specified above.
> Hercules will try to configure this automatically, but this
> behaviour can be overridden, e.g. if you wish to set custom rules or automatic
> configuration fails.
> If you set this to false, you must manually ensure packets end up in the
> right queue.
> Some network interfaces do not support multiple queues, in which case automatic
> configuration will fail and the server will not start with this option enabled.
> In such cases, you may simply set this option to
> *false*
> without further configuration.
> The default value is
> *true*.

## PER-DESTINATION OVERRIDES

The maximum number of paths and payload size to use can be overridden,
either for a single destination host or an entire destination AS.
Additionally, the paths to use towards each destination can be specified via
path rules.
In case both an AS rule and a Host rule match a destination, the Host rule
takes precedence.
Choosing specific paths is useful if too many paths to the destination are
available, or if certain paths are known to perform better.
Choosing a specific payload length is useful if the MTU listed in the SCION
path metadata is higher than the actual MTU the path(s) can support.
In such a case, Hercules' automatic payload size selection will fail, and it
must be set manually.

Destination-host rules are set as follows:

\[\[**DestinationHosts**]]

> **HostAddr**=*str*

> > The destination host this rule applies to.

> \[**NumPaths**=*int*]

> > The maximum number of paths to use towards the destination.
> > Specifying this is optional, if not set the value of
> > **DefaultNumPaths**
> > will be used.

> \[**PathSpec**=\[\[ *str*,] *,]*]

> > A list of AS-interface sequences that must be present on the paths towards
> > the destination.
> > Specifying this is optional, if not set no path restrictions are applied.

> \[**Payloadlen**=*int*]

> > The payload length to use for packets towards this destination.
> > Note that the payload length does not include the Hercules, UDP or SCION
> > headers.
> > Hence, the value should be set slightly lower than the actual maximum MTU.
> > Usually, a value of ca. 100 bytes less than the MTU is fine, but it may need to
> > be smaller for longer paths.
> > Specifying this is optional, if not set Hercules will attempt to pick the
> > right payload size based on the SCION path metadata and the MTU of the sending
> > interface.

\[\[**DestinationASes**]]

> **IA**=*str*

> > The destination ISD-AS this rule applies to

> \[**NumPaths**=*int*]

> \[**PathSpec**=\[\[ *str*,] *,]*]

> \[**Payloadlen**=*int*]

> > These options work the same as in the
> > **DestinationHosts**
> > rules described above.

Example: The following set of rules specifies that

*	For transfers to the host
	*17-ffaa:1:fe2,1.1.1.1*:

	*	Transfers may use up to 42 paths.
	*	The paths must contain either the AS-interface sequence
		      17-f:f:f 1 -&gt; 17:f:f:a 2
		      OR 1-f:0:0 22 .

*	For transfers to the host
	*18-a:b:c,2.2.2.2*:

	*	Up to two paths should be used.
	*	Automatic MTU selection is overridden and a payload length of 1000B is used.

*	For transfers to any other host in AS
	*18-a:b:c*:

	*	A payload length of 1400 should be used.

Example:

	[[DestinationHosts]]
	HostAddr = "17-ffa:1:fe2,1.1.1.1"
	NumPaths = 42
	PathSpec = [
	["17-f:f:f 1", "17-f:f:a 2"],
	["1-f:0:0 22"],
	]
	
	[[DestinationHosts]]
	HostAddr = "18-a:b:c,2.2.2.2"
	NumPaths = 2
	Payloadlen = 1000
	
	[[DestinationASes]]
	IA = "18-a:b:c"
	Payloadlen = 1400

# FILES

*/usr/local/etc/hercules.conf*

> Default configuration file

*/usr/local/share/doc/hercules/hercules.conf.sample*

> Example config file showcasing the available options.

# SEE ALSO

hcp(1),
hercules-monitor(1),
hercules-server(1),
hercules(7)

Further information about Hercules is available on
[https://github.com/netsec-ethz/hercules](https://github.com/netsec-ethz/hercules).
For more information about SCION, please see
[https://scion-architecture.net](https://scion-architecture.net).

# AUTHORS

Network Security Group, ETH Z&#252;rich

# CAVEATS

Two security issues are present when Hercules is run as the root user:
First, because the receiving-side Hercules server simply writes data to the file
specified by the sender and no authentication of the sender is performed,
a sender may overwrite arbitrary system files.
Second, because the sending-side Hercules server simply copies data from the
file specified by the user and no authentication of the user is performed,
a user may copy arbitrary system files to the destination server.
To mitigate these issues, it is recommended that you set the
**DropUser**
and/or
**ChrootDir**
options described above.

Void Linux - October 29, 2024
