package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// These specify how to read the config file
type HostConfig struct {
	HostAddr addr.Addr
	NumPaths int
	PathSpec []PathSpec
}
type ASConfig struct {
	IA       addr.IA
	NumPaths int
	PathSpec []PathSpec
}

// This wraps snet.UDPAddr to make the config parsing work
type UDPAddr struct {
	addr *snet.UDPAddr
}

func (a *UDPAddr) UnmarshalText(text []byte) error {
	var err error
	a.addr, err = snet.ParseUDPAddr(string(text))
	return err
}

type Interface struct {
	iface *net.Interface
}

func (i *Interface) UnmarshalText(text []byte) error {
	var err error
	i.iface, err = net.InterfaceByName(string(text))
	return err
}

type UserGroup struct {
	User      string // Username supplied in the config file
	uidLookup int    // User ID, looked up and filled when parsing config
	Group     string
	gidLookup int
}

type MonitorConfig struct {
	DestinationHosts []HostConfig
	DestinationASes  []ASConfig
	DefaultNumPaths  int
	MonitorSocket    string
	ListenAddress    UDPAddr
	MonitorHTTP      string
	MonitorHTTPS     string
	TLSCert          string
	TLSKey           string
	Interfaces       []Interface
	UserMap          map[string]*UserGroup
	ClientCACerts    []string
	// The following are not used by the monitor, they are listed here for completeness
	ServerSocket    string
	XDPZeroCopy     bool
	Queue           int
	ConfigureQueues bool
	EnablePCC       bool
	RateLimit       int
	NumThreads      int
}

type PathRules struct {
	Hosts           map[addr.Addr]HostConfig
	ASes            map[addr.IA]ASConfig
	DefaultNumPaths int
}

func findPathRule(p *PathRules, dest *snet.UDPAddr) Destination {
	a := addr.Addr{
		IA:   dest.IA,
		Host: addr.MustParseHost(dest.Host.IP.String()),
	}
	confHost, ok := p.Hosts[a]
	if ok {
		return Destination{
			hostAddr: dest,
			pathSpec: &confHost.PathSpec,
			numPaths: confHost.NumPaths,
		}
	}
	conf, ok := p.ASes[dest.IA]
	if ok {
		return Destination{
			hostAddr: dest,
			pathSpec: &conf.PathSpec,
			numPaths: conf.NumPaths,
		}
	}
	return Destination{
		hostAddr: dest,
		pathSpec: &[]PathSpec{},
		numPaths: p.DefaultNumPaths,
	}
}

const defaultMonitorHTTP = ":8000"
const defaultMonitorHTTPS = "disabled"
// Disabled by default because further config (certs) is needed

// Decode the config file and fill in any unspecified values with defaults.
// Will exit if an error occours or a required value is not specified.
func readConfig(configFile string) (MonitorConfig, PathRules) {
	var config MonitorConfig
	meta, err := toml.DecodeFile(configFile, &config)
	if err != nil {
		fmt.Printf("Error reading configuration file (%v): %v\n", configFile, err)
		os.Exit(1)
	}
	if len(meta.Undecoded()) > 0 {
		fmt.Printf("Unknown element(s) in config file: %v\n", meta.Undecoded())
		os.Exit(1)
	}

	if config.DefaultNumPaths == 0 {
		fmt.Println("Config: Default number of paths to use not set, using 1.")
		config.DefaultNumPaths = 1
	}

	if config.MonitorSocket == "" {
		config.MonitorSocket = defaultMonitorSocket
	}

	if config.MonitorHTTP == "" {
		config.MonitorHTTP = defaultMonitorHTTP
	}

	if config.MonitorHTTPS == "" {
		config.MonitorHTTPS = defaultMonitorHTTPS
	}
	if config.MonitorHTTPS != "disabled" {
		if config.TLSCert == "" || config.TLSKey == "" {
			fmt.Println("HTTPS enabled and no certificate or key specified")
			os.Exit(1)
		}
		if len(config.ClientCACerts) == 0 {
			fmt.Println("HTTPS enabled and no certificates for client authentication specified")
			os.Exit(1)
		}
	}

	// This is required
	if config.ListenAddress.addr == nil {
		fmt.Println("Error: Listening address not specified")
		os.Exit(1)
	}

	if config.ListenAddress.addr.Host.Port == 0 {
		fmt.Println("No listening port specified")
		os.Exit(1)
	}

	if len(config.Interfaces) == 0 {
		fmt.Println("Error: No interfaces specified")
		os.Exit(1)
	}

	for _, u := range config.UserMap {
		userLookup, err := user.Lookup(u.User)
		if err != nil {
			fmt.Printf("User lookup error: %v\n", u.User)
			os.Exit(1)
		}
		u.uidLookup, err = strconv.Atoi(userLookup.Uid)
		if err != nil {
			os.Exit(1)
		}

		groupLookup, err := user.LookupGroup(u.Group)
		if err != nil {
			fmt.Printf("Group lookup error: %v\n", u.Group)
			os.Exit(1)
		}
		u.gidLookup, err = strconv.Atoi(groupLookup.Gid)
		if err != nil {
			os.Exit(1)
		}
	}

	pathRules := PathRules{}
	// It would be nice not to have to do this dance and specify the maps directly in the config file,
	// but the toml package crashes if the keys are addr.Addr

	pathRules.Hosts = map[addr.Addr]HostConfig{}
	for _, host := range config.DestinationHosts {
		numpaths := config.DefaultNumPaths
		if host.NumPaths != 0 {
			numpaths = host.NumPaths
		}
		pathspec := []PathSpec{}
		if host.PathSpec != nil {
			pathspec = host.PathSpec
		}
		pathRules.Hosts[host.HostAddr] = HostConfig{
			HostAddr: host.HostAddr,
			NumPaths: numpaths,
			PathSpec: pathspec,
		}
	}

	pathRules.ASes = map[addr.IA]ASConfig{}
	for _, as := range config.DestinationASes {
		numpaths := config.DefaultNumPaths
		if as.NumPaths != 0 {
			numpaths = as.NumPaths
		}
		pathspec := []PathSpec{}
		if as.PathSpec != nil {
			pathspec = as.PathSpec
		}
		pathRules.ASes[as.IA] = ASConfig{
			IA:       as.IA,
			NumPaths: numpaths,
			PathSpec: pathspec,
		}
	}

	pathRules.DefaultNumPaths = config.DefaultNumPaths

	return config, pathRules
}
