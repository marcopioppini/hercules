package main

import (
	"fmt"
	"os"

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
type MonitorConfig struct {
	DestinationHosts []HostConfig
	DestinationASes  []ASConfig
	DefaultNumPaths  int
	MonitorSocket    string
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
		config.MonitorSocket = "/var/herculesmon.sock" // TODO should be in /var/run
	}

	fmt.Println(config.MonitorSocket, config.MonitorSocket == "", config.MonitorSocket == "")

	pathRules := PathRules{}
	// TODO Would be nice not to have to do this dance and specify the maps directly in the config file,
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
