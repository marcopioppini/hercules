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
	pm    *PathManager
	dst   *Destination
	paths []PathMeta // Paths to use for sending
}

type PathMeta struct {
	path    snet.Path
	iface   *net.Interface
	enabled bool // Indicates whether this path can be used at the moment
}

// Packet header (including lower-level headers) as used by the C part
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
		pm:    pm,
		dst:   dst,
		paths: make([]PathMeta, 1),
	}
}

func initNewPathsToDestination(pm *PathManager, dst *Destination) (*PathsToDestination, error) {
	return &PathsToDestination{
		pm:    pm,
		dst:   dst,
		paths: make([]PathMeta, dst.numPaths),
	}, nil
}

func (ptd *PathsToDestination) choosePaths() bool {
	var err error
	allPaths, err := GlobalQuerier.Query(context.Background(), ptd.dst.hostAddr.IA)
	if err != nil {
		fmt.Println("Error querying paths:", err)
		return false
	}

	if allPaths == nil || len(allPaths) == 0 {
		return false
	}

	// This is a transfer within the same AS, use empty path
	if allPaths[0].UnderlayNextHop() == nil {
		allPaths[0] = path.Path{
			Src:           ptd.pm.src.IA,
			Dst:           ptd.dst.hostAddr.IA,
			DataplanePath: path.Empty{},
			NextHop:       ptd.dst.hostAddr.NextHop,
		}
	}

	// Restrict to paths that use one of the specified interfaces
	availablePaths := ptd.pm.filterPathsByActiveInterfaces(allPaths)

	if ptd.pm.payloadLen != 0 {
		// Chunk length fixed by a previous path lookup, we need to pick paths compatible with it
		availablePaths = ptd.pm.filterPathsByMTU(availablePaths)
	}
	if len(availablePaths) == 0 {
		log.Error(fmt.Sprintf("no paths to destination %s", ptd.dst.hostAddr.IA.String()))
		return false
	}

	ptd.chooseNewPaths(availablePaths)

	if ptd.pm.payloadLen == 0 {
		// No payloadlen set yet, we set it to the maximum that all selected paths and interfaces support
		maxPayloadlen := HerculesMaxPktsize
		for _, path := range ptd.paths {
			pathMTU := int(path.path.Metadata().MTU)
			underlayHeaderLen, scionHeaderLen := getPathHeaderlen(path.path)
			if pathMTU == 0 {
				// Empty path has MTU 0, so let's just use the interface's MTU
				// If the real MTU is smaller than the interface's,
				// a payloadlength can be supplied when submitting the transfer.
				pathMTU = path.iface.MTU - scionHeaderLen - underlayHeaderLen
			}
			pathPayloadlen := pathMTU - scionHeaderLen
			maxPayloadlen = min(maxPayloadlen, pathPayloadlen)
			// Cap to Hercules' max pkt size
			maxPayloadlen = min(maxPayloadlen, HerculesMaxPktsize-scionHeaderLen-underlayHeaderLen)
			// Check the interface's MTU is large enough
			if maxPayloadlen+scionHeaderLen+underlayHeaderLen-14 > path.iface.MTU {
				// Packet exceeds the interface MTU
				// 14 is the size of the ethernet header, which is not included in the interface's MTU
				fmt.Printf("Interface (%v) MTU too low, decreasing payload length", path.iface.Name)
				maxPayloadlen = path.iface.MTU - underlayHeaderLen - scionHeaderLen
			}
		}
		ptd.pm.payloadLen = maxPayloadlen
		fmt.Println("Set payload length to", ptd.pm.payloadLen)
	}

	return true
}

func (ptd *PathsToDestination) chooseNewPaths(availablePaths []PathWithInterface) bool {
	updated := false

	// pick paths
	picker := makePathPicker(ptd.dst.pathSpec, availablePaths, ptd.dst.numPaths)
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
	if len(pathSet) == 0 {
		ptd.paths = []PathMeta{}
		return false
	}
	for i, _ := range ptd.paths {
		// Ensures unused paths slots are not accidentally marked enabled if
		// the number of paths has decreased since the last time
		ptd.paths[i].enabled = false
	}
	for i, path := range pathSet {
		log.Info(fmt.Sprintf("\t%s", path.path))
		ptd.paths[i].path = path.path
		ptd.paths[i].enabled = true
		ptd.paths[i].iface = path.iface
		updated = true
	}
	return updated
}
