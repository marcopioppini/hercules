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
	"context"
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
)

var GlobalQuerier snet.PathQuerier

type PathsToDestination struct {
	pm             *PathManager
	dst            *Destination
	allPaths       []snet.Path
	paths          []PathMeta // nil indicates that the destination is in the same AS as the sender and we can use an empty path
	canSendLocally bool // (only if destination in same AS) indicates if we can send packets
}

type PathMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	iface       *net.Interface
	enabled     bool // Indicates whether this path can be used at the moment
	updated     bool // Indicates whether this path needs to be synced to the C path
}

type HerculesPathHeader struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

func initNewPathsToDestinationWithEmptyPath(pm *PathManager, dst *Destination) *PathsToDestination {
	dst.hostAddr.NextHop = &net.UDPAddr{
		IP:   dst.hostAddr.Host.IP,
		Port: topology.EndhostPort,
	}
	return &PathsToDestination{
		pm:         pm,
		dst:        dst,
		paths:      make([]PathMeta, 1),
	}
}

func initNewPathsToDestination(pm *PathManager, src *snet.UDPAddr, dst *Destination) (*PathsToDestination, error) {
	return &PathsToDestination{
		pm:         pm,
		dst:        dst,
		allPaths:   nil,
		paths:      make([]PathMeta, dst.numPaths),
	}, nil
}

func (ptd *PathsToDestination) hasUsablePaths() bool {
	if ptd.paths == nil {
		return ptd.canSendLocally
	}
	for _, path := range ptd.paths {
		if path.enabled {
			return true
		}
	}
	return false
}

func (ptd *PathsToDestination) choosePaths() bool {
	var err error
	ptd.allPaths, err = GlobalQuerier.Query(context.Background(), ptd.dst.hostAddr.IA)
	if err != nil {
		fmt.Println("Error querying paths:", err)
		return false
	}

	if ptd.allPaths == nil {
		return false
	}

	if ptd.allPaths[0].UnderlayNextHop() == nil {
		ptd.allPaths[0] = path.Path{
			Src:           ptd.pm.src.IA,
			Dst:           ptd.dst.hostAddr.IA,
			DataplanePath: path.Empty{},
			NextHop:       ptd.dst.hostAddr.NextHop,
		}
	}

	availablePaths := ptd.pm.filterPathsByActiveInterfaces(ptd.allPaths)
	if len(availablePaths) == 0 {
		log.Error(fmt.Sprintf("no paths to destination %s", ptd.dst.hostAddr.IA.String()))
	}

	if ptd.pm.mtu != 0 {
		// MTU fixed by a previous path lookup, we need to pick paths compatible with it
		availablePaths = ptd.pm.filterPathsByMTU(availablePaths)
	}

	// TODO Ensure this still does the right thing when the number of paths decreases (how to test?)
	ptd.chooseNewPaths(availablePaths)

	if ptd.pm.mtu == 0{
		// No MTU set yet, we set it to the maximum that all selected paths and interfaces support
		minMTU := HerculesMaxPktsize
		for _, path := range ptd.paths {
			if path.path.Metadata().MTU < uint16(minMTU){
				minMTU = int(path.path.Metadata().MTU)
			}
			if path.iface.MTU < minMTU {
				minMTU = path.iface.MTU
			}
		}
		ptd.pm.mtu = minMTU
		ptd.pm.mtu = 1200 // FIXME temp
	}

	return true
}

func (ptd *PathsToDestination) chooseNewPaths(availablePaths []PathWithInterface) bool {
	updated := false

	// pick paths
	picker := makePathPicker(ptd.dst.pathSpec, availablePaths, ptd.dst.numPaths)
	fmt.Println(availablePaths)
	var pathSet []PathWithInterface
	disjointness := 0 // negative number denoting how many network interfaces are shared among paths (to be maximized)
	maxRuleIdx := 0   // the highest index of a PathSpec that is used (to be minimized)
	for i := ptd.dst.numPaths; i > 0; i-- {
		picker.reset(i)
		for picker.nextRuleSet() { // iterate through different choices of PathSpecs to use
			if pathSet != nil && maxRuleIdx < picker.maxRuleIdx() { // ignore rule set, if path set with lower maxRuleIndex is known
				continue // due to the iteration order, we cannot break here
			}
			for picker.nextPick() { // iterate through different choices of paths obeying the rules of the current set of PathSpecs
				curDisjointness := picker.disjointnessScore()
				if pathSet == nil || disjointness < curDisjointness { // maximize disjointness
					disjointness = curDisjointness
					maxRuleIdx = picker.maxRuleIdx()
					pathSet = picker.getPaths()
				}
			}
		}
		if pathSet != nil { // if no path set of size i found, try with i-1
			break
		}
	}

	log.Info(fmt.Sprintf("[Destination %s] using %d paths:", ptd.dst.hostAddr.IA, len(pathSet)))
	if (len(pathSet) == 0){
		ptd.paths = []PathMeta{}
		return false
	}
	for i, path := range pathSet {
		log.Info(fmt.Sprintf("\t%s", path.path))
		ptd.paths[i].path = path.path
		ptd.paths[i].enabled = true
		ptd.paths[i].updated = true
		ptd.paths[i].iface = path.iface
		updated = true
	}
	return updated
}
