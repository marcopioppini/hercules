HERCULES-MONITOR(1) - General Commands Manual

# NAME

**hercules-monitor** - Monitor component of the Hercules file transfer system

# SYNOPSIS

**hercules-monitor**
\[**-c**&nbsp;*conffile*]

# DESCRIPTION

**hercules-monitor**
is the monitor component of the Hercules file transfer sytem.
The monitor is the link between users and the Hercules server.
Users interact with the monitor via its HTTP API.
The monitor interacts with the server component via a local Unix socket.
Hercules is configured via a configuration file (see
hercules.conf(5)).

The monitor and server processes must be started and stopped together, you
should not restart one without also restarting the other.
The provided systemd service files ensure this, if you use a different method
to run Hercules you must ensure this yourself.

The options are as follows:

**-c** *conffile*

> Use the specified configuration file.
> By default,
> **hercules-monitor**
> will first look for a file named
> *hercules.conf*
> in its working directory, then for the default config file,
> */usr/local/etc/hercules.conf*.
> See
> hercules.conf(5)
> for configuration options.

# ENVIRONMENT

`SCION_DAEMON_ADDRESS`

> If the SCION daemon is listening on a non-default port,
> `SCION_DAEMON_ADDRESS`
> can be set to its listening address and port.

# FILES

*/usr/local/etc/hercules.conf*

> Default configuration file

*/var/run/herculesmon.sock*

> Default Unix socket path

# SEE ALSO

hcp(1),
hercules-server(1),
hercules.conf(5),
hercules(7)

Further information about Hercules is available on
[https://github.com/netsec-ethz/hercules](https://github.com/netsec-ethz/hercules).
For more information about SCION, please see
[https://scion-architecture.net](https://scion-architecture.net).

# AUTHORS

Network Security Group, ETH Z&#252;rich

# CAVEATS

See
hercules.conf(5)s CAVEATS.

Void Linux - October 29, 2024
