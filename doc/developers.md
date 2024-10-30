# Development

See the main readme for how to build Hercules from source.
When debugging or developing it may be desirable to run Hercules manually and
not via systemd, for example to attach a debugger. To do so, simply:

1. Start the monitor: `sudo ./hercules-monitor`
2. In a second shell, start the server: `sudo ./hercules-server`

- It may be useful to uncomment some of the lines marked "for debugging" at the
  top of the Makefile.
- The script `test.sh` is a very simple test utility. It will try 3 sets of
  transfers: a file, a directory, and 2 files concurrently.
  You can use it to sanity-check any code changes you make.
  You will need to point the script to two hosts to use for the test transfers.
  In order to use it, adjust the definitions at the top of the file
  (hostnames, addresses and interfaces).
  The script further relies on you having ssh keys set up for those two hosts.
  Depending on the network cards you may need to comment in the two lines with
  `ConfigureQueues = false`.
- The `xdpdump` tool
  (<https://github.com/xdp-project/xdp-tools/tree/master/xdp-dump>) is useful
  for seeing packets received via XDP. Similar to `tcpdump`, but for XDP.

## Docs
Documentation pertaining to the server is located in the `doc/` directory, and
in `hcp/` for `hcp`.
If you make changes to the manual files, run `make docs` to rebuild the
markdown versions of the man pages.

