// Copyright 2019 ETH Zurich
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

package main

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/vishvananda/netlink"
)

type Destination struct {
	hostAddr   *snet.UDPAddr
	pathSpec   *[]PathSpec
	numPaths   int
	payloadlen int
}

type PathManager struct {
	interfaces map[int]*net.Interface
	dst        *PathsToDestination
	src        *snet.UDPAddr
	payloadLen int // The payload length to use for this transfer. Paths must be able to transfer payloads of at least this size.
}

type PathWithInterface struct {
	path  snet.Path
	iface *net.Interface
}

// Setting payloadlen to 0 means automatic selection
func initNewPathManager(interfaces []*net.Interface, dst *Destination, src *snet.UDPAddr, payloadLen int) (*PathManager, error) {
	ifMap := make(map[int]*net.Interface)
	for _, iface := range interfaces {
		ifMap[iface.Index] = iface
	}

	pm := &PathManager{
		interfaces: ifMap,
		src:        src,
		dst:        &PathsToDestination{},
		payloadLen: payloadLen,
	}

	if src.IA == dst.hostAddr.IA {
		pm.dst = initNewPathsToDestinationWithEmptyPath(pm, dst)
	} else {
		var err error
		pm.dst, err = initNewPathsToDestination(pm, dst)
		if err != nil {
			return nil, err
		}
	}

	return pm, nil
}

func (pm *PathManager) choosePaths() bool {
	return pm.dst.choosePaths()
}

func (pm *PathManager) filterPathsByActiveInterfaces(pathsAvail []snet.Path) []PathWithInterface {
	pathsFiltered := []PathWithInterface{}
	for _, path := range pathsAvail {
		iface, err := pm.interfaceForRoute(path.UnderlayNextHop().IP)
		if err != nil {
		} else {
			pathsFiltered = append(pathsFiltered, PathWithInterface{path, iface})
		}
	}
	return pathsFiltered
}

// Don't consider paths that cannot fit the required payload length
func (pm *PathManager) filterPathsByMTU(pathsAvail []PathWithInterface) []PathWithInterface {
	pathsFiltered := []PathWithInterface{}
	for _, path := range pathsAvail {
		// The path MTU refers to the maximum length of the SCION headers and payload,
		// but not including the lower-level (ethernet/ip/udp) headers
		pathMTU := int(path.path.Metadata().MTU)
		underlayHeaderLen, scionHeaderLen := getPathHeaderlen(path.path)
		if pathMTU == 0 {
			// Empty path has length 0, let's just use the interface's MTU
			pathMTU = path.iface.MTU - scionHeaderLen - underlayHeaderLen
		}
		pathPayloadlen := pathMTU - scionHeaderLen
		// The interface MTU refers to the maximum length of the entire packet,
		// excluding the ethernet header (14B)
		ifacePayloadLen := path.iface.MTU - (scionHeaderLen + underlayHeaderLen - 14)

		if pathPayloadlen >= pm.payloadLen && ifacePayloadLen >= pm.payloadLen {
			pathsFiltered = append(pathsFiltered, path)
		}
	}
	return pathsFiltered
}

func (pm *PathManager) interfaceForRoute(ip net.IP) (*net.Interface, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return nil, fmt.Errorf("could not find route for destination %s: %s", ip, err)
	}

	for _, route := range routes {
		if iface, ok := pm.interfaces[route.LinkIndex]; ok {
			fmt.Printf("route to %s via #%d (%s)\n", ip, route.LinkIndex, pm.interfaces[route.LinkIndex].Name)
			return iface, nil
		}
	}
	return nil, fmt.Errorf("no interface active for sending to %s", ip)
}
