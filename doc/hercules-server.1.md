HERCULES-SERVER(1) - General Commands Manual

# NAME

**hercules-server** - Server component of the Hercules file transfer system

# SYNOPSIS

**hercules-server**
\[**-c**&nbsp;*conffile*]

# DESCRIPTION

**hercules-server**
is the server component of the Hercules file transfer system.
The server's task is to run the actual file transfers.
The server receives tasks from the monitor and informs the monitor of
transfer progress via a local Unix socket.
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
> **hercules-server**
> will first look for a file named
> *hercules.conf*
> in its working directory, then for the default config file,
> */usr/local/etc/hercules.conf*.
> See
> hercules.conf(5)
> for configuration options.

# FILES

*/usr/local/etc/hercules.conf*

> Default configuration file

*/var/run/hercules.sock*

> Default Unix socket path

# SEE ALSO

hcp(1),
hercules-monitor(1),
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
