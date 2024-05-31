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
	"github.com/scionproto/scion/pkg/snet"
	"github.com/vishvananda/netlink"
	"net"
	"time"
)

type Destination struct {
	hostAddr *snet.UDPAddr
	pathSpec *[]PathSpec
	numPaths int
}

type PathManager struct {
	numPathSlotsPerDst int
	interfaces         map[int]*net.Interface
	dst                *PathsToDestination
	src                *snet.UDPAddr
	syncTime           time.Time
	maxBps             uint64
}

type PathWithInterface struct {
	path  snet.Path
	iface *net.Interface
}

type AppPathSet map[snet.PathFingerprint]PathWithInterface

const numPathsResolved = 20

func initNewPathManager(interfaces []*net.Interface, dst *Destination, src *snet.UDPAddr, maxBps uint64) (*PathManager, error) {
	ifMap := make(map[int]*net.Interface)
	for _, iface := range interfaces {
		ifMap[iface.Index] = iface
	}

	pm := &PathManager{
		interfaces: ifMap,
		src:        src,
		dst:        &PathsToDestination{},
		syncTime:   time.Unix(0, 0),
		maxBps:     maxBps,
	}

	if src.IA == dst.hostAddr.IA {
		pm.dst = initNewPathsToDestinationWithEmptyPath(pm, dst)
	} else {
		var err error
		pm.dst, err = initNewPathsToDestination(pm, src, dst)
		if err != nil {
			return nil, err
		}
	}

	return pm, nil
}

func (pm *PathManager) canSendToDest() bool {
	return pm.dst.hasUsablePaths()
}

func (pm *PathManager) choosePaths() bool {
	return pm.dst.choosePaths()
}

func (pm *PathManager) filterPathsByActiveInterfaces(pathsAvail []snet.Path) AppPathSet {
	pathsFiltered := make(AppPathSet)
	for _, path := range pathsAvail {
		iface, err := pm.interfaceForRoute(path.UnderlayNextHop().IP)
		if err != nil {
		} else {
			pathsFiltered[snet.Fingerprint(path)] = PathWithInterface{path, iface}
		}
	}
	return pathsFiltered
}

func (pm *PathManager) interfaceForRoute(ip net.IP) (*net.Interface, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return nil, fmt.Errorf("could not find route for destination %s: %s", ip, err)
	}

	fmt.Println(pm.interfaces)
	for _, route := range routes {
		if iface, ok := pm.interfaces[route.LinkIndex]; ok {
			fmt.Printf("sending via #%d (%s) to %s\n", route.LinkIndex, pm.interfaces[route.LinkIndex].Name, ip)
			return iface, nil
		}
	}
	return nil, fmt.Errorf("no interface active for sending to %s", ip)
}
